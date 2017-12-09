#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from ansible.module_utils.aws.elb_utils import get_elb, convert_tg_name_to_arn

from ansible.module_utils.ec2 import boto3_conn, get_aws_connection_info, camel_dict_to_snake_dict, ec2_argument_spec, get_ec2_security_group_ids_from_names, \
    ansible_dict_to_boto3_tag_list, boto3_tag_list_to_ansible_dict, compare_aws_tags, HAS_BOTO3

from botocore.exceptions import ClientError
import traceback
import time


class ElasticLoadBalancerV2:

    def wait_for_status(self, elb_name, status):
        polling_increment_secs = 15
        max_retries = self.module.params.get('wait_timeout') // polling_increment_secs
        status_achieved = False

        for x in range(0, max_retries):
            try:
                response = get_elb(self.connection, self.module, elb_name)
                if response['State']['Code'] == status:
                    status_achieved = True
                    break
                else:
                    time.sleep(polling_increment_secs)
            except ClientError as e:
                self.module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

        result = response

        return status_achieved, result

    def get_elb_attributes(self):
        """
        Get load balancer attributes
        :param module:
        :param elb_arn:
        :return:
        """

        try:
            elb_attributes = boto3_tag_list_to_ansible_dict(self.connection.describe_load_balancer_attributes(LoadBalancerArn=elb_arn)['Attributes'])
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

        # Replace '.' with '_' in attribute key names to make it more Ansibley
        return dict((k.replace('.', '_'), v) for k, v in elb_attributes.items())


    def delete_elb(self):
        """
        Delete a load balancer
        :return:
        """

        changed = False
        elb = get_elb(connection, module)

        if elb:
            try:
                connection.delete_load_balancer(LoadBalancerArn=elb['LoadBalancerArn'])
                changed = True
            except ClientError as e:
                module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
            except NoCredentialsError as e:
                module.fail_json(msg="AWS authentication problem. " + e.message, exception=traceback.format_exc())

        module.exit_json(changed=changed)


    def change_subnets(self, elb):
        """
        If necessary, modify elb subnets to match user passed parameters
        :return:
        """

        changed = False

        if set(_get_subnet_ids_from_subnet_list(elb['AvailabilityZones'])) != set(params['Subnets']):
            try:
                self.connection.set_subnets(LoadBalancerArn=elb['LoadBalancerArn'], Subnets=params['Subnets'])
            except ClientError as e:
                module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
            changed = True

        return changed


class ApplicationLoadBalancer(ElasticLoadBalancerV2):

    def __init__(self, connection, connection_ec2, module):
        """

        :param connection: boto3 connection
        :param module: Ansible module
        """
        self.connection = connection
        self.connection_ec2 = connection_ec2
        self.module = module
        self.elb = get_elb(connection, module, module.params.get("name"))
        if self.elb is not None:
            self.elb_attributes = self.get_elb_attributes()
        else:
            self.elb_attributes = None
        self.changed = False
        self.new_load_balancer = False

        # Ansible module parameters
        self.name = module.params.get("name")
        self.subnets = module.params.get("subnets")
        if module.params.get('security_groups') is not None:
            try:
                self.security_groups = get_ec2_security_group_ids_from_names(module.params.get('security_groups'), self.connection_ec2, boto3=True)
            except ValueError as e:
                module.fail_json(msg=str(e), exception=traceback.format_exc())
            except ClientError as e:
                module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
        else:
            self.security_groups = module.params.get('security_groups')
        self.scheme = module.params.get("scheme")
        if module.params.get("tags"):
            self.tags = ansible_dict_to_boto3_tag_list(module.params.get("tags"))
        else:
            self.tags = None
        self.purge_tags = module.params.get("purge_tags")
        self.access_logs_enabled = module.params.get("access_logs_enabled")
        self.access_logs_s3_bucket = module.params.get("access_logs_s3_bucket")
        self.access_logs_s3_prefix = module.params.get("access_logs_s3_prefix")
        self.deletion_protection = module.params.get("deletion_protection")
        self.idle_timeout = module.params.get("idle_timeout")
        self.wait = module.params.get("wait")

    def create_elb(self):
        """
        Create a load balancer
        :return:
        """

        # Required parameters
        params = dict()
        params['Name'] = self.name
        params['Type'] = 'application'
        
        # Other parameters
        if self.subnets is not None:
            params['Subnets'] = self.subnets
        if self.security_groups is not None:
            params['SecurityGroups'] = self.security_groups
        params['Scheme'] = self.scheme
        if self.tags is not None:
            params['Tags'] = self.tags

        try:
            self.elb = self.connection.create_load_balancer(**params)['LoadBalancers'][0]
            self.changed = True
            self.new_load_balancer = True
        except ClientError as e:
            self.module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

        if self.wait:
            status_achieved, new_elb = self.wait_for_status('active', self.name)

    def update_elb_attributes(self):
        """
        Update ELB attributes if required
        :return:
        """

        update_attributes = []

        if self.access_logs_enabled and self.elb_attributes['access_logs_s3_enabled'] != "true":
            update_attributes.append({'Key': 'access_logs.s3.enabled', 'Value': "true"})
        if not self.access_logs_enabled and self.elb_attributes['access_logs_s3_enabled'] != "false":
            update_attributes.append({'Key': 'access_logs.s3.enabled', 'Value': 'false'})
        if self.access_logs_s3_bucket is not None and self.access_logs_s3_bucket != self.elb_attributes['access_logs_s3_bucket']:
            update_attributes.append({'Key': 'access_logs.s3.bucket', 'Value': self.access_logs_s3_bucket})
        if self.access_logs_s3_prefix is not None and self.access_logs_s3_prefix != self.elb_attributes['access_logs_s3_prefix']:
            update_attributes.append({'Key': 'access_logs.s3.prefix', 'Value': self.access_logs_s3_prefix})
        if self.deletion_protection and self.elb_attributes['deletion_protection_enabled'] != "true":
            update_attributes.append({'Key': 'deletion_protection.enabled', 'Value': "true"})
        if not self.deletion_protection and self.elb_attributes['deletion_protection_enabled'] != "false":
            update_attributes.append({'Key': 'deletion_protection.enabled', 'Value': "false"})
        if self.idle_timeout is not None and str(self.idle_timeout) != self.elb_attributes['idle_timeout_timeout_seconds']:
            update_attributes.append({'Key': 'idle_timeout.timeout_seconds', 'Value': str(self.idle_timeout)})

        if update_attributes:
            try:
                self.connection.modify_load_balancer_attributes(LoadBalancerArn=self.elb['LoadBalancerArn'], Attributes=update_attributes)
                self.changed = True
            except ClientError as e:
                # Something went wrong setting attributes. If this ELB was created during this task, delete it to leave a consistent state
                if self.new_load_balancer:
                    self.connection.delete_load_balancer(LoadBalancerArn=self.elb['LoadBalancerArn'])
                module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))




#class NetworkLoadBalancer(ElasticLoadBalancerV2):


class ALBListeners():

    def __init__(self, connection, module, elb_arn):

        self.connection = connection
        self.module = module
        self.elb_arn = elb_arn
        self.listeners = self._ensure_listeners_default_action_has_arn(module.params.get("listeners"))
        self.current_listeners = self._get_elb_listeners()
        self.purge_listeners = module.params.get("purge_listeners")
        self.changed = False

    def _get_elb_listeners(self):
        """
        Get ELB listeners

        :return:
        """

        try:
            listener_paginator = self.connection.get_paginator('describe_listeners')
            return (listener_paginator.paginate(LoadBalancerArn=self.elb_arn).build_full_result())['Listeners']
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    def _ensure_listeners_default_action_has_arn(self, listeners):
        """
        If a listener DefaultAction has been passed with a Target Group Name instead of ARN, lookup the ARN and
        replace the name.

        :param listeners: a list of listener dicts
        :return: the same list of dicts ensuring that each listener DefaultActions dict has TargetGroupArn key. If a TargetGroupName key exists, it is removed.
        """

        if not listeners:
            listeners = []

        for listener in listeners:
            if 'TargetGroupName' in listener['DefaultActions'][0]:
                listener['DefaultActions'][0]['TargetGroupArn'] = convert_tg_name_to_arn(self.connection, self.module, listener['DefaultActions'][0]['TargetGroupName'])
                del listener['DefaultActions'][0]['TargetGroupName']

        return listeners

    def compare_listeners(self):
        """

        :return:
        """
        listeners_to_modify = []
        listeners_to_delete = []

        # Check each current listener port to see if it's been passed to the module
        for current_listener in self.current_listeners:
            current_listener_passed_to_module = False
            for new_listener in self.listeners[:]:
                new_listener['Port'] = int(new_listener['Port'])
                if current_listener['Port'] == new_listener['Port']:
                    current_listener_passed_to_module = True
                    # Remove what we match so that what is left can be marked as 'to be added'
                    self.listeners.remove(new_listener)
                    modified_listener = self._compare_listener(current_listener, new_listener)
                    if modified_listener:
                        modified_listener['Port'] = current_listener['Port']
                        modified_listener['ListenerArn'] = current_listener['ListenerArn']
                        listeners_to_modify.append(modified_listener)
                    break

            # If the current listener was not matched against passed listeners and purge is True, mark for removal
            if not current_listener_passed_to_module and self.purge_listeners:
                listeners_to_delete.append(current_listener['ListenerArn'])

        listeners_to_add = self.listeners

        return listeners_to_add, listeners_to_modify, listeners_to_delete

    def _compare_listener(self, current_listener, new_listener):
        """
        Compare two listeners.

        :param current_listener:
        :param new_listener:
        :return:
        """

        modified_listener = {}

        # Port
        if current_listener['Port'] != new_listener['Port']:
            modified_listener['Port'] = new_listener['Port']

        # Protocol
        if current_listener['Protocol'] != new_listener['Protocol']:
            modified_listener['Protocol'] = new_listener['Protocol']

        # If Protocol is HTTPS, check additional attributes
        if current_listener['Protocol'] == 'HTTPS' and new_listener['Protocol'] == 'HTTPS':
            # Cert
            if current_listener['SslPolicy'] != new_listener['SslPolicy']:
                modified_listener['SslPolicy'] = new_listener['SslPolicy']
            if current_listener['Certificates'][0]['CertificateArn'] != new_listener['Certificates'][0]['CertificateArn']:
                modified_listener['Certificates'] = []
                modified_listener['Certificates'].append({})
                modified_listener['Certificates'][0]['CertificateArn'] = new_listener['Certificates'][0]['CertificateArn']
        elif current_listener['Protocol'] != 'HTTPS' and new_listener['Protocol'] == 'HTTPS':
            modified_listener['SslPolicy'] = new_listener['SslPolicy']
            modified_listener['Certificates'] = []
            modified_listener['Certificates'].append({})
            modified_listener['Certificates'][0]['CertificateArn'] = new_listener['Certificates'][0]['CertificateArn']

        # Default action
        #   We wont worry about the Action Type because it is always 'forward'
        if current_listener['DefaultActions'][0]['TargetGroupArn'] != new_listener['DefaultActions'][0]['TargetGroupArn']:
            modified_listener['DefaultActions'] = []
            modified_listener['DefaultActions'].append({})
            modified_listener['DefaultActions'][0]['TargetGroupArn'] = new_listener['DefaultActions'][0]['TargetGroupArn']
            modified_listener['DefaultActions'][0]['Type'] = 'forward'

        if modified_listener:
            return modified_listener
        else:
            return None


class ALBListener():

    def __init__(self, connection, module, listener, elb_arn):

        self.connection = connection
        self.module = module
        self.listener = listener
        self.elb_arn = elb_arn

    def add_listener(self):

        try:

            # Rules is not a valid parameter for create_listener
            if 'Rules' in self.listener:
                self.listener.pop('Rules')
            self.connection.create_listener(LoadBalancerArn=self.elb_arn, **self.listener)
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    def modify_listener(self):

        try:
            # Rules is not a valid parameter for modify_listener
            if 'Rules' in self.listener:
                self.listener.pop('Rules')
            self.connection.modify_listener(**self.listener)
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    def delete_listener(self):

        try:
            self.connection.delete_listener(ListenerArn=self.listener)
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
