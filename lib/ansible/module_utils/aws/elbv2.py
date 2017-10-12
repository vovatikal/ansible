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


class ElasticLoadBalancer:

    def __init__(self, connection, module, params):
        """

        :param connection:
        :param module:
        """
        self.connection = connection
        self.module = module
        self.params = params


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



class ApplicationLoadBalancer(ElasticLoadBalancer):


class NetworkLoadBalancer(ElasticLoadBalancer):


    changed = False
new_load_balancer = False
params = dict()
params['Name'] = module.params.get("name")
params['Subnets'] = module.params.get("subnets")
subnet_mappings = module.params.get("subnet_mappings")
params['Scheme'] = module.params.get("scheme")
if module.params.get("tags"):
    params['Tags'] = ansible_dict_to_boto3_tag_list(module.params.get("tags"))
purge_tags = module.params.get("purge_tags")
access_logs_enabled = module.params.get("access_logs_enabled")
access_logs_s3_bucket = module.params.get("access_logs_s3_bucket")
access_logs_s3_prefix = module.params.get("access_logs_s3_prefix")
deletion_protection = module.params.get("deletion_protection")
idle_timeout = module.params.get("idle_timeout")

import time
import collections
from copy import deepcopy
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import string_types
from ansible.module_utils.ec2 import boto3_conn, get_aws_connection_info, camel_dict_to_snake_dict, ec2_argument_spec, get_ec2_security_group_ids_from_names, \
    ansible_dict_to_boto3_tag_list, boto3_tag_list_to_ansible_dict, compare_aws_tags, HAS_BOTO3

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    HAS_BOTO3 = False


def convert_tg_name_to_arn(connection, module, tg_name):

    try:
        response = connection.describe_target_groups(Names=[tg_name])
    except ClientError as e:
        module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    tg_arn = response['TargetGroups'][0]['TargetGroupArn']

    return tg_arn


def wait_for_status(connection, module, elb_arn, status):
    polling_increment_secs = 15
    max_retries = module.params.get('wait_timeout') // polling_increment_secs
    status_achieved = False

    for x in range(0, max_retries):
        try:
            response = connection.describe_load_balancers(LoadBalancerArns=[elb_arn])
            if response['LoadBalancers'][0]['State']['Code'] == status:
                status_achieved = True
                break
            else:
                time.sleep(polling_increment_secs)
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    result = response
    return status_achieved, result


def _get_subnet_ids_from_subnet_list(subnet_list):

    subnet_id_list = []
    for subnet in subnet_list:
        subnet_id_list.append(subnet['SubnetId'])

    return subnet_id_list


def get_elb_listeners(connection, module, elb_arn):

    try:
        listener_paginator = connection.get_paginator('describe_listeners')
        return (listener_paginator.paginate(LoadBalancerArn=elb_arn).build_full_result())['Listeners']
    except ClientError as e:
        module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))


def get_elb_attributes(connection, module, elb_arn):

    try:
        elb_attributes = boto3_tag_list_to_ansible_dict(connection.describe_load_balancer_attributes(LoadBalancerArn=elb_arn)['Attributes'])
    except ClientError as e:
        module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    # Replace '.' with '_' in attribute key names to make it more Ansibley
    return dict((k.replace('.', '_'), v) for k, v in elb_attributes.items())


def get_listener(connection, module, elb_arn, listener_port):
    """
    Get a listener based on the port provided.

    :param connection: ELBv2 boto3 connection
    :param module: Ansible module object
    :param listener_port:
    :return:
    """

    try:
        listener_paginator = connection.get_paginator('describe_listeners')
        listeners = (listener_paginator.paginate(LoadBalancerArn=elb_arn).build_full_result())['Listeners']
    except ClientError as e:
        module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    l = None

    for listener in listeners:
        if listener['Port'] == listener_port:
            l = listener
            break

    return l


def get_elb(connection, module):
    """
    Get an application load balancer based on name. If not found, return None

    :param connection: ELBv2 boto3 connection
    :param module: Ansible module object
    :return: Dict of load balancer attributes or None if not found
    """

    try:
        load_balancer_paginator = connection.get_paginator('describe_load_balancers')
        return (load_balancer_paginator.paginate(Names=[module.params.get("name")]).build_full_result())['LoadBalancers'][0]
    except ClientError as e:
        if e.response['Error']['Code'] == 'LoadBalancerNotFound':
            return None
        else:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))


def get_listener_rules(connection, module, listener_arn):

    try:
        return connection.describe_rules(ListenerArn=listener_arn)['Rules']
    except ClientError as e:
        module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))


def ensure_listeners_default_action_has_arn(connection, module, listeners):
    """
    If a listener DefaultAction has been passed with a Target Group Name instead of ARN, lookup the ARN and
    replace the name.

    :param connection: ELBv2 boto3 connection
    :param module: Ansible module object
    :param listeners: a list of listener dicts
    :return: the same list of dicts ensuring that each listener DefaultActions dict has TargetGroupArn key. If a TargetGroupName key exists, it is removed.
    """

    if not listeners:
        listeners = []

    for listener in listeners:
        if 'TargetGroupName' in listener['DefaultActions'][0]:
            listener['DefaultActions'][0]['TargetGroupArn'] = convert_tg_name_to_arn(connection, module, listener['DefaultActions'][0]['TargetGroupName'])
            del listener['DefaultActions'][0]['TargetGroupName']

    return listeners


def ensure_rules_action_has_arn(connection, module, rules):
    """
    If a rule Action has been passed with a Target Group Name instead of ARN, lookup the ARN and
    replace the name.

    :param connection: ELBv2 boto3 connection
    :param module: Ansible module object
    :param rules: a list of rule dicts
    :return: the same list of dicts ensuring that each rule Actions dict has TargetGroupArn key. If a TargetGroupName key exists, it is removed.
    """

    for rule in rules:
        if 'TargetGroupName' in rule['Actions'][0]:
            rule['Actions'][0]['TargetGroupArn'] = convert_tg_name_to_arn(connection, module, rule['Actions'][0]['TargetGroupName'])
            del rule['Actions'][0]['TargetGroupName']

    return rules


def compare_listener(current_listener, new_listener):
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


def compare_condition(current_conditions, condition):
    """

    :param current_conditions:
    :param condition:
    :return:
    """

    condition_found = False

    for current_condition in current_conditions:
        if current_condition['Field'] == condition['Field'] and current_condition['Values'][0] == condition['Values'][0]:
            condition_found = True
            break

    return condition_found


def compare_rule(current_rule, new_rule):
    """
    Compare two rules.

    :param current_rule:
    :param new_rule:
    :return:
    """

    modified_rule = {}

    # Priority
    if current_rule['Priority'] != new_rule['Priority']:
        modified_rule['Priority'] = new_rule['Priority']

    # Actions
    #   We wont worry about the Action Type because it is always 'forward'
    if current_rule['Actions'][0]['TargetGroupArn'] != new_rule['Actions'][0]['TargetGroupArn']:
        modified_rule['Actions'] = []
        modified_rule['Actions'].append({})
        modified_rule['Actions'][0]['TargetGroupArn'] = new_rule['Actions'][0]['TargetGroupArn']
        modified_rule['Actions'][0]['Type'] = 'forward'

    # Conditions
    modified_conditions = []
    for condition in new_rule['Conditions']:
        if not compare_condition(current_rule['Conditions'], condition):
            modified_conditions.append(condition)

    if modified_conditions:
        modified_rule['Conditions'] = modified_conditions

    return modified_rule


def compare_listeners(connection, module, current_listeners, new_listeners, purge_listeners):
    """
    Compare listeners and return listeners to add, listeners to modify and listeners to remove
    Listeners are compared based on port

    :param connection: ELBv2 boto3 connection
    :param module: Ansible module object
    :param current_listeners:
    :param new_listeners:
    :param purge_listeners:
    :return:
    """

    listeners_to_modify = []
    listeners_to_delete = []

    # Check each current listener port to see if it's been passed to the module
    for current_listener in current_listeners:
        current_listener_passed_to_module = False
        for new_listener in new_listeners[:]:
            new_listener['Port'] = int(new_listener['Port'])
            if current_listener['Port'] == new_listener['Port']:
                current_listener_passed_to_module = True
                # Remove what we match so that what is left can be marked as 'to be added'
                new_listeners.remove(new_listener)
                modified_listener = compare_listener(current_listener, new_listener)
                if modified_listener:
                    modified_listener['Port'] = current_listener['Port']
                    modified_listener['ListenerArn'] = current_listener['ListenerArn']
                    listeners_to_modify.append(modified_listener)
                break

        # If the current listener was not matched against passed listeners and purge is True, mark for removal
        if not current_listener_passed_to_module and purge_listeners:
            listeners_to_delete.append(current_listener['ListenerArn'])

    listeners_to_add = new_listeners

    return listeners_to_add, listeners_to_modify, listeners_to_delete


def compare_rules(connection, module, current_listeners, listener):

    """
    Compare rules and return rules to add, rules to modify and rules to remove
    Rules are compared based on priority

    :param connection: ELBv2 boto3 connection
    :param module: Ansible module object
    :param current_listeners: list of listeners currently associated with the ELB
    :param listener: dict object of a listener passed by the user
    :return:
    """

    # Run through listeners looking for a match (by port) to get the ARN
    for current_listener in current_listeners:
        if current_listener['Port'] == listener['Port']:
            listener['ListenerArn'] = current_listener['ListenerArn']
            break

    # If the listener exists (i.e. has an ARN) get rules for the listener
    if 'ListenerArn' in listener:
        current_rules = get_listener_rules(connection, module, listener['ListenerArn'])
    else:
        current_rules = []

    rules_to_modify = []
    rules_to_delete = []

    for current_rule in current_rules:
        current_rule_passed_to_module = False
        for new_rule in listener['Rules'][:]:
            if current_rule['Priority'] == new_rule['Priority']:
                current_rule_passed_to_module = True
                # Remove what we match so that what is left can be marked as 'to be added'
                listener['Rules'].remove(new_rule)
                modified_rule = compare_rule(current_rule, new_rule)
                if modified_rule:
                    modified_rule['Priority'] = int(current_rule['Priority'])
                    modified_rule['RuleArn'] = current_rule['RuleArn']
                    modified_rule['Actions'] = new_rule['Actions']
                    modified_rule['Conditions'] = new_rule['Conditions']
                    rules_to_modify.append(modified_rule)
                break

        # If the current rule was not matched against passed rules, mark for removal
        if not current_rule_passed_to_module and not current_rule['IsDefault']:
            rules_to_delete.append(current_rule['RuleArn'])

    rules_to_add = listener['Rules']

    return rules_to_add, rules_to_modify, rules_to_delete


def create_or_update_elb_listeners(connection, module, elb):
    """Create or update ELB listeners. Return true if changed, else false"""

    listener_changed = False
    # Ensure listeners are using Target Group ARN not name
    listeners = ensure_listeners_default_action_has_arn(connection, module, module.params.get("listeners"))
    purge_listeners = module.params.get("purge_listeners")

    # Does the ELB have any listeners exist?
    current_listeners = get_elb_listeners(connection, module, elb['LoadBalancerArn'])

    listeners_to_add, listeners_to_modify, listeners_to_delete = compare_listeners(connection, module, current_listeners, deepcopy(listeners), purge_listeners)

    # Add listeners
    for listener_to_add in listeners_to_add:
        try:
            listener_to_add['LoadBalancerArn'] = elb['LoadBalancerArn']
            # Rules is not a valid parameter for create_listener
            if 'Rules' in listener_to_add:
                listener_to_add.pop('Rules')
            response = connection.create_listener(**listener_to_add)
            # Add the new listener
            current_listeners.append(response['Listeners'][0])
            listener_changed = True
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    # Modify listeners
    for listener_to_modify in listeners_to_modify:
        try:
            # Rules is not a valid parameter for modify_listener
            if 'Rules' in listener_to_modify:
                listener_to_modify.pop('Rules')
            connection.modify_listener(**listener_to_modify)
            listener_changed = True
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    # Delete listeners
    for listener_to_delete in listeners_to_delete:
        try:
            connection.delete_listener(ListenerArn=listener_to_delete)
            listener_changed = True
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    # For each listener, check rules
    for listener in deepcopy(listeners):
        if 'Rules' in listener:
            # Ensure rules are using Target Group ARN not name
            listener['Rules'] = ensure_rules_action_has_arn(connection, module, listener['Rules'])
            rules_to_add, rules_to_modify, rules_to_delete = compare_rules(connection, module, current_listeners, listener)

            # Get listener based on port so we can use ARN
            looked_up_listener = get_listener(connection, module, elb['LoadBalancerArn'], listener['Port'])

            # Delete rules
            for rule in rules_to_delete:
                try:
                    connection.delete_rule(RuleArn=rule)
                    listener_changed = True
                except ClientError as e:
                    module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

            # Add rules
            for rule in rules_to_add:
                try:
                    rule['ListenerArn'] = looked_up_listener['ListenerArn']
                    rule['Priority'] = int(rule['Priority'])
                    connection.create_rule(**rule)
                    listener_changed = True
                except ClientError as e:
                    module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

            # Modify rules
            for rule in rules_to_modify:
                try:
                    del rule['Priority']
                    connection.modify_rule(**rule)
                    listener_changed = True
                except ClientError as e:
                    module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    return listener_changed


def create_or_update_elb(connection, connection_ec2, module):
    """Create ELB or modify main attributes. json_exit here"""

    changed = False
    new_load_balancer = False
    params = dict()
    params['Name'] = module.params.get("name")
    params['Subnets'] = module.params.get("subnets")
    try:
        params['SecurityGroups'] = get_ec2_security_group_ids_from_names(module.params.get('security_groups'), connection_ec2, boto3=True)
    except ValueError as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    except ClientError as e:
        module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
    except NoCredentialsError as e:
        module.fail_json(msg="AWS authentication problem. " + e.message, exception=traceback.format_exc())

    params['Scheme'] = module.params.get("scheme")
    if module.params.get("tags"):
        params['Tags'] = ansible_dict_to_boto3_tag_list(module.params.get("tags"))
    purge_tags = module.params.get("purge_tags")
    access_logs_enabled = module.params.get("access_logs_enabled")
    access_logs_s3_bucket = module.params.get("access_logs_s3_bucket")
    access_logs_s3_prefix = module.params.get("access_logs_s3_prefix")
    deletion_protection = module.params.get("deletion_protection")
    idle_timeout = module.params.get("idle_timeout")

    # Does the ELB currently exist?
    elb = get_elb(connection, module)

    if elb:
        # ELB exists so check subnets, security groups and tags match what has been passed

        # Subnets
        if set(_get_subnet_ids_from_subnet_list(elb['AvailabilityZones'])) != set(params['Subnets']):
            try:
                connection.set_subnets(LoadBalancerArn=elb['LoadBalancerArn'], Subnets=params['Subnets'])
            except ClientError as e:
                module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
            changed = True

        # Security Groups
        if set(elb['SecurityGroups']) != set(params['SecurityGroups']):
            try:
                connection.set_security_groups(LoadBalancerArn=elb['LoadBalancerArn'], SecurityGroups=params['SecurityGroups'])
            except ClientError as e:
                module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
            changed = True

        # Tags - only need to play with tags if tags parameter has been set to something
        if module.params.get("tags"):
            try:
                elb_tags = connection.describe_tags(ResourceArns=[elb['LoadBalancerArn']])['TagDescriptions'][0]['Tags']
            except ClientError as e:
                module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

            # Delete necessary tags
            tags_need_modify, tags_to_delete = compare_aws_tags(boto3_tag_list_to_ansible_dict(elb_tags), boto3_tag_list_to_ansible_dict(params['Tags']),
                                                                purge_tags)
            if tags_to_delete:
                try:
                    connection.remove_tags(ResourceArns=[elb['LoadBalancerArn']], TagKeys=tags_to_delete)
                except ClientError as e:
                    module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
                changed = True

            # Add/update tags
            if tags_need_modify:
                try:
                    connection.add_tags(ResourceArns=[elb['LoadBalancerArn']], Tags=params['Tags'])
                except ClientError as e:
                    module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
                changed = True

    else:
        try:
            elb = connection.create_load_balancer(**params)['LoadBalancers'][0]
            changed = True
            new_load_balancer = True
        except ClientError as e:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

        if module.params.get("wait"):
            status_achieved, new_elb = wait_for_status(connection, module, elb['LoadBalancerArn'], 'active')

    # Now set ELB attributes. Use try statement here so we can remove the ELB if this stage fails
    update_attributes = []

    # Get current attributes
    current_elb_attributes = get_elb_attributes(connection, module, elb['LoadBalancerArn'])

    if access_logs_enabled and current_elb_attributes['access_logs_s3_enabled'] != "true":
        update_attributes.append({'Key': 'access_logs.s3.enabled', 'Value': "true"})
    if not access_logs_enabled and current_elb_attributes['access_logs_s3_enabled'] != "false":
        update_attributes.append({'Key': 'access_logs.s3.enabled', 'Value': 'false'})
    if access_logs_s3_bucket is not None and access_logs_s3_bucket != current_elb_attributes['access_logs_s3_bucket']:
        update_attributes.append({'Key': 'access_logs.s3.bucket', 'Value': access_logs_s3_bucket})
    if access_logs_s3_prefix is not None and access_logs_s3_prefix != current_elb_attributes['access_logs_s3_prefix']:
        update_attributes.append({'Key': 'access_logs.s3.prefix', 'Value': access_logs_s3_prefix})
    if deletion_protection and current_elb_attributes['deletion_protection_enabled'] != "true":
        update_attributes.append({'Key': 'deletion_protection.enabled', 'Value': "true"})
    if not deletion_protection and current_elb_attributes['deletion_protection_enabled'] != "false":
        update_attributes.append({'Key': 'deletion_protection.enabled', 'Value': "false"})
    if idle_timeout is not None and str(idle_timeout) != current_elb_attributes['idle_timeout_timeout_seconds']:
        update_attributes.append({'Key': 'idle_timeout.timeout_seconds', 'Value': str(idle_timeout)})

    if update_attributes:
        try:
            connection.modify_load_balancer_attributes(LoadBalancerArn=elb['LoadBalancerArn'], Attributes=update_attributes)
            changed = True
        except ClientError as e:
            # Something went wrong setting attributes. If this ELB was created during this task, delete it to leave a consistent state
            if new_load_balancer:
                connection.delete_load_balancer(LoadBalancerArn=elb['LoadBalancerArn'])
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    # Now, if required, set ELB listeners. Use try statement here so we can remove the ELB if this stage fails
    try:
        listener_changed = create_or_update_elb_listeners(connection, module, elb)
        if listener_changed:
            changed = True
    except ClientError as e:
        # Something went wrong setting listeners. If this ELB was created during this task, delete it to leave a consistent state
        if new_load_balancer:
            connection.delete_load_balancer(LoadBalancerArn=elb['LoadBalancerArn'])
        module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    # Get the ELB again
    elb = get_elb(connection, module)

    # Get the ELB listeners again
    elb['listeners'] = get_elb_listeners(connection, module, elb['LoadBalancerArn'])

    # For each listener, get listener rules
    for listener in elb['listeners']:
        listener['rules'] = get_listener_rules(connection, module, listener['ListenerArn'])

    # Get the ELB attributes again
    elb.update(get_elb_attributes(connection, module, elb['LoadBalancerArn']))

    # Convert to snake_case
    snaked_elb = camel_dict_to_snake_dict(elb)

    # Get the tags of the ELB
    elb_tags = connection.describe_tags(ResourceArns=[elb['LoadBalancerArn']])['TagDescriptions'][0]['Tags']
    snaked_elb['tags'] = boto3_tag_list_to_ansible_dict(elb_tags)

    module.exit_json(changed=changed, **snaked_elb)


def delete_elb(connection, module):

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


def main():

    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            access_logs_enabled=dict(type='bool'),
            access_logs_s3_bucket=dict(type='str'),
            access_logs_s3_prefix=dict(type='str'),
            deletion_protection=dict(default=False, type='bool'),
            idle_timeout=dict(type='int'),
            listeners=dict(type='list'),
            name=dict(required=True, type='str'),
            purge_listeners=dict(default=True, type='bool'),
            purge_tags=dict(default=True, type='bool'),
            subnets=dict(type='list'),
            subnet_mappings=dict(type='list'),
            scheme=dict(default='internet-facing', choices=['internet-facing', 'internal']),
            state=dict(choices=['present', 'absent'], type='str'),
            tags=dict(default={}, type='dict'),
            wait_timeout=dict(type='int'),
            wait=dict(type='bool')
        )
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=[
                               ('state', 'present', ['subnets'])
                           ],
                           required_one_of=[['subnets', 'subnet_mappings']],
                           required_together=(
                               ['access_logs_enabled', 'access_logs_s3_bucket', 'access_logs_s3_prefix']
                           )
                           )

    # Quick check of listeners parameters
    listeners = module.params.get("listeners")
    if listeners is not None:
        for listener in listeners:
            for key in listener.keys():
                if key not in ['Protocol', 'Port', 'SslPolicy', 'Certificates', 'DefaultActions', 'Rules']:
                    module.fail_json(msg="listeners parameter contains invalid dict keys. Should be one of 'Protocol', "
                                         "'Port', 'SslPolicy', 'Certificates', 'DefaultActions', 'Rules'.")
                # Make sure Port is always an integer
                elif key == 'Port':
                    listener[key] = int(listener[key])

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)

    if region:
        connection = boto3_conn(module, conn_type='client', resource='elbv2', region=region, endpoint=ec2_url, **aws_connect_params)
        connection_ec2 = boto3_conn(module, conn_type='client', resource='ec2', region=region, endpoint=ec2_url, **aws_connect_params)
    else:
        module.fail_json(msg="region must be specified")

    state = module.params.get("state")

    if state == 'present':
        create_or_update_elb(connection, connection_ec2, module)
    else:
        delete_elb(connection, module)

if __name__ == '__main__':
    main()
