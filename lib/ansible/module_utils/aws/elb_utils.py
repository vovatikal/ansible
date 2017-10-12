from ansible.module_utils.ec2 import boto3_conn, get_aws_connection_info, camel_dict_to_snake_dict, ec2_argument_spec, get_ec2_security_group_ids_from_names, \
    ansible_dict_to_boto3_tag_list, boto3_tag_list_to_ansible_dict, compare_aws_tags, HAS_BOTO3

import boto3
from botocore.exceptions import ClientError
import traceback


def get_elb(connection, module, elb_name):
    """
    Get an application load balancer based on name. If not found, return None

    :param connection: boto3 elbv2 connection
    :param module: Ansible module
    :param elb_name: Name of load balancer to get
    :return:
    """

    try:
        load_balancer_paginator = connection.get_paginator('describe_load_balancers')
        return (load_balancer_paginator.paginate(Names=[elb_name]).build_full_result())['LoadBalancers'][0]
    except ClientError as e:
        if e.response['Error']['Code'] == 'LoadBalancerNotFound':
            return None
        else:
            module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))


def get_elb_listener_rules(connection, module, listener_arn):

    try:
        return connection.describe_rules(ListenerArn=listener_arn)['Rules']
    except ClientError as e:
        module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))


def convert_tg_name_to_arn(connection, module, tg_name):
    """
    Using a target group's name, get the ARN
    :param connection:
    :param module:
    :param tg_name:
    :return:
    """

    try:
        response = connection.describe_target_groups(Names=[tg_name])
    except ClientError as e:
        module.fail_json(msg=e.message, exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    tg_arn = response['TargetGroups'][0]['TargetGroupArn']

    return tg_arn
