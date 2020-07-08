#!/usr/local/bin/python

import os
import sys
import time
from datetime import datetime, timedelta
import requests
import argparse
import json
from pprint import pprint
from argparse import RawTextHelpFormatter
import  boto3
from botocore.exceptions import ClientError

PROD_AUTH_URL = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize"
RECOMMENDATION = {'Recommendation': None, 'Details': None}
DEFAULT_HEADERS = {'Accept': 'application/json', 'Content-type': 'Application/json'}

class CommandFormatter(argparse.ArgumentDefaultsHelpFormatter,
                       argparse.RawDescriptionHelpFormatter):
    """Argparse formatter to display __doc__ string correctly"""
    pass

parser = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=RawTextHelpFormatter, add_help=False)
                                 # formatter_class=CommandFormatter, add_help=False)
parser.add_argument('-S', '--sddc-id', required=True, help='SDDC ID of the affected instance')
parser.add_argument('-I', '--ip-address', help='IP Address of affected instance')
parser.add_argument('-i', '--instance-id', help='Instance ID of affected instance')
parser.add_argument('-n', '--no-console-output', action='store_true',
                    help='Do not dump instance console output')
parser.add_argument('-a', '--autoscaler-tasks', action='store_true',
                    help='(Only) Query the autosscaler tasks for the SDDC instance')
parser.add_argument('-s', '--host-state', action='store_true',
                    help='Query the host state using RTS script')
parser.add_argument('-p', '--time-period', type=int, choices=[1,3,6,12,24,36,48,72], default=3,
                    help='Time range in hours to search for AWS cloudwatch metrics')
parser.add_argument('-h', '--help', action='help')


def api_request(url, method='get', headers=None, data=None, params=None):
    if method == 'get':
        return requests.get(url, headers=headers, data=data, params=params)
    elif method == 'put':
        return requests.put(url, headers=headers, data=data, params=params)
    else:
        return requests.post(url, headers=headers, data=data, params=params)

def get_api_token(url=PROD_AUTH_URL, token=None):
    if not token:
        token = os.environ.get("VMC_REFRESH_TOKEN", None)
    if not token:
        print("Please set your VMC_REFRESH_TOKEN environment variable. Quitting")
        return None
    resp = api_request(url, method='post', headers={'Content-type': 'application/x-www-form-urlencoded'},
                       data={'refresh_token': token})
    if resp.status_code < 200 or resp.status_code > 202:
        print("Unable to obtain access token from refresg token. Quitting")
        return None
    return resp.json()['access_token']

def get_sddc_org_region(sddc_id):
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    url = 'https://vmc.vmware.com/vmc/api/operator/sddcs/{}'.format(sddc_id)
    resp = api_request(url, headers=headers)
    if resp.status_code < 200 or resp.status_code > 202:
        print("Unable to obtain SDDC with ID " + sddc_id + ". Quitting...")
        return None, None
    return (resp.json()['org_id'], resp.json()['resource_config']['sddc_manifest']['esx_ami']['region'],
        resp.json()['resource_config']['vpc_info']['id'])

def get_autoscaler_tasks(org_id, sddc_id, ip_address):
    token = get_api_token()
    url = 'https://vmc.vmware.com/vmc/autoscaler/api/orgs/{}/sddcs/{}/get-tasks'.format(org_id, sddc_id)
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    resp = api_request(url, headers=headers)
    if resp.status_code < 200 or resp.status_code > 202:
        print("Unable to obtain autoscaler tasks for SDDC with ID " + sddc_id + ". Quitting...")
        return None
    for sddc_task in resp.json()['sddc_task_status']:
        if 'cluster_task_status' in sddc_task:
            for cluster_task in sddc_task['cluster_task_status']:
                if cluster_task['hostname'] == ip_address:
                    url = 'https://vmc.vmware.com/vmc/autoscaler/api/operator/tasks/{}'.format(cluster_task['task_id'])
                    r = api_request(url, headers=headers)
                    print(json.dumps(r.json(), indent=2, sort_keys=False))
                    if r.json()['task_type'] == 'REMEDIATE-EBS-HOST':
                        replace_ebs_task = None
                        replace_ebs_task = r.json()['params']['replaceEbsHostTaskId']
                        if replace_ebs_task:
                            url = 'https://vmc.vmware.com/vmc/autoscaler/api/operator/tasks/{}'.format(replace_ebs_task)
                            r = api_request(url, headers=headers)
                            print(json.dumps(r.json(), indent=2, sort_keys=False))

def get_rts_host_state(sddc_id, ip_address):
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    url = 'https://internal.vmc.vmware.com/vmc/rts/api/operator/script'
    rts_script_data = "scriptId:vcenter_host_manage,sddc-id:{},esx:{},action:state,reason:test".format(sddc_id, ip_address)
    data = {"requestBody": rts_script_data}
    resp = api_request(url, method='post', headers=headers, data=json.dumps(data))
    if resp.status_code < 200 or resp.status_code > 202:
        print("Unable to obtain host state from RTS for SDDC " + sddc_id + " and host " + ip_address)
        return None
    url = 'https://internal.vmc.vmware.com/vmc/rts/api/operator/tasks/{}'.format(resp.json()['id'])
    for i in range(0, 5):
        time.sleep(20)
        resp = api_request(url, headers=headers)
        if resp.status_code < 200 or resp.status_code > 202:
            print("Unable to obtain RTS task details")
            return None
        if resp.json()['status'] == 'FINISHED':
            output = json.loads(resp.json()['params']['SCRIPTDATA']['data'])
            #print(output['output'])
            print(json.dumps(output['output'], indent=2, sort_keys=False))
            #print(resp.json()['params']['SCRIPTDATA']['data'])
            return 0
    print("Timed out waiting for RTS task to complete")
    return None

def get_instance_failure(sddc_id, org_id, region, vpc_id, ip_addr, inst_id, no_console_logs=True, time_period=3):
    instance_id = None
    hardware_failure = False
    instance_status_failure = False
    system_status_failure = False
    first_instance_status_failure = None
    first_system_status_failure = None
    last_instance_status_failure = None
    last_system_status_failure = None
    period = 60
    failure_data = {'instance_status_failure': instance_status_failure, 'system_status_failure': system_status_failure}
    failure_data['sddc_id'] = sddc_id
    failure_data['org_id'] = org_id
    failure_data['region'] = region
    token = get_api_token()
    headers = DEFAULT_HEADERS
    failure_data['hardware_error'] = hardware_failure
    headers.update({'csp-auth-token': token})
    url = 'https://vmc.vmware.com/vmc/api/operator/aws/credentials?orgId={}'.format(org_id)
    resp = api_request(url, method='post', headers=headers)
    if resp.status_code < 200 or resp.status_code > 204:
        print("Unable to obtain AWS credentials for Org " + org_id + " and sddc ID " + sddc_id)
        return None
    session_token = resp.json()['aws_credentials']['session_token']
    access_key = resp.json()['aws_credentials']['awsaccess_key_id']
    secret_key = resp.json()['aws_credentials']['awssecret_key']
    ec2_client = boto3.client('ec2', aws_access_key_id=access_key,
                          aws_secret_access_key=secret_key, region_name=region,
                          aws_session_token=session_token)
    ec2_resource = boto3.resource('ec2', aws_access_key_id=access_key,
                                  aws_secret_access_key=secret_key, region_name=region,
                                  aws_session_token=session_token)
    
    if ip_addr:
        failure_data['ip_address'] = ip_addr
        filters = [{'Name': 'private-ip-address', 'Values': [ip_addr]}, {'Name': 'vpc-id', 'Values': [vpc_id]}]
        r = ec2_resource.instances.filter(Filters=filters)
        for item in r:
            instance_id = item.instance_id
            failure_data['instance_id'] = instance_id
            failure_data['instance_type'] = item.instance_type
            failure_data['instance_state'] = item.state
            failure_data['launch_time'] = item.launch_time
        if not instance_id:
            # Instance with matching IP was not found. Display autoscaler tasks and exit
            get_autoscaler_tasks(org_id, sddc_id, ip_addr)
            print('')
            #return failure_data 
            if not inst_id:
                pprint(failure_data)
                sys.exit(1)

    if instance_id:
        if not no_console_logs:
            resp = ec2_client.get_console_output(InstanceId=instance_id)
            value = resp.get('Output', 'No Serial Logs available')
            if 'Hardware Error' in value or 'hardware vendor' in value:
                hardware_failure = True
            home = os.path.expanduser("~")
            filename = os.path.join(home, instance_id + '-console.txt')
            with open(filename, 'w') as f:
                f.write(value.encode('utf-8'))
            print("Saving console output to file: " + filename)

    if not instance_id:
        instance_id = inst_id
        # resp = ec2_client.describe_instances(Filters=[{'Name': 'instance-id', 'Values': [instance_id,]}])
        try:
            resp = ec2_client.describe_instances(InstanceIds=[instance_id,])
            if len(resp['Reservations']) > 0:
                if not 'launch_time' in failure_data:
                    failure_data['launch_time'] = resp['Reservations'][0]['Instances'][0]['LaunchTime']
                if not 'instance_type' in failure_data:
                    failure_data['instance_type'] = resp['Reservations'][0]['Instances'][0]['InstanceType']
                if not 'instance_state' in failure_data:
                    failure_data['instance_state'] = resp['Reservations'][0]['Instances'][0]['State']
        except ClientError as e:
            print(e.message)
            pass

    if instance_id:
        try:
            resp = ec2_client.describe_instance_status(InstanceIds=[instance_id,])
            # print(resp)
            if len(resp['InstanceStatuses']) > 0:
                failure_data['instance_status'] = resp['InstanceStatuses'][0]['InstanceStatus']['Details']
                failure_data['system_status'] = resp['InstanceStatuses'][0]['SystemStatus']['Details']
                if 'Events' in resp['InstanceStatuses'][0]:
                    failure_data['scheduled_events'] = resp['InstanceStatuses'][0]['Events']
        except ClientError as e:
            print(e.message)
            pass

    if time_period > 24:
        period = 300
    cw_client = boto3.client('cloudwatch', aws_access_key_id=access_key,
                          aws_secret_access_key=secret_key, region_name=region,
                          aws_session_token=session_token)
    resp = cw_client.get_metric_statistics(Namespace='AWS/EC2', MetricName='StatusCheckFailed_Instance',
                                           Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                                           StartTime=datetime.utcnow() - timedelta(hours=time_period),
                                           EndTime=datetime.utcnow(), Period=period,
                                           Statistics=['Average'])
    instance_statuses = sorted(resp['Datapoints'], key= lambda i : i['Timestamp'])
    for item in instance_statuses:
        if item['Average'] > 0:
            first_instance_status_failure = item['Timestamp']
            instance_status_failure = True
            break
    instance_statuses = sorted(resp['Datapoints'], key= lambda i : i['Timestamp'], reverse=True)
    for item in instance_statuses:
        if item['Average'] > 0:
            last_instance_status_failure = item['Timestamp']
            instance_status_failure = True
            break

    resp = cw_client.get_metric_statistics(Namespace='AWS/EC2', MetricName='StatusCheckFailed_System',
                                           Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                                           StartTime=datetime.utcnow() - timedelta(hours=time_period),
                                           EndTime=datetime.utcnow(), Period=period,
                                           Statistics=['Average'])
    system_statuses = sorted(resp['Datapoints'], key= lambda i : i['Timestamp'])
    for item in system_statuses:
        if item['Average'] > 0:
            first_system_status_failure = item['Timestamp']
            system_status_failure = True
            break
    for item in sorted(resp['Datapoints'], key= lambda i : i['Timestamp'], reverse=True):
        if item['Average'] > 0:
            last_system_status_failure = item['Timestamp']
            system_status_failure = True
            break
    
    failure_data['instance_status_failure'] = instance_status_failure
    failure_data['system_status_failure'] = system_status_failure
    failure_data['first_instance_status_failure'] = first_instance_status_failure
    failure_data['first_system_status_failure'] = first_system_status_failure
    failure_data['last_instance_status_failure'] = last_instance_status_failure
    failure_data['last_system_status_failure'] = last_system_status_failure
    failure_data['hardware_error'] = hardware_failure
    return failure_data

def print_data(data):
    if data['first_instance_status_failure']:
        data['first_instance_status_failure'] = str(data['first_instance_status_failure'])
    if data['first_system_status_failure']:
        data['first_system_status_failure'] = str(data['first_system_status_failure'])
    if data['last_instance_status_failure']:
        data['last_instance_status_failure'] = str(data['last_instance_status_failure'])
    if data['last_system_status_failure']:
        data['last_system_status_failure'] = str(data['last_instance_status_failure'])
    if 'launch_time' in data:
        data['launch_time'] = str(data['launch_time'])
    if 'instance_status' in data and 'ImpairedSince' in data['instance_status'][0]:
        data['instance_status'][0]['ImpairedSince'] = str(data['instance_status'][0]['ImpairedSince'])
    if 'system_status' in data and 'ImpairedSince' in data['system_status'][0]:
        data['system_status'][0]['ImpairedSince'] = str(data['system_status'][0]['ImpairedSince'])
    pprint(data)


if __name__ == '__main__':

    args = parser.parse_args()
    if not args.ip_address and not args.instance_id:
        print("Must specific either an instance IP or ID. Quitting...")
        sys.exit(1)
    org_id, region, vpc_id = get_sddc_org_region(args.sddc_id)
    if not org_id:
        sys.exit(1)

    if args.autoscaler_tasks:
        get_autoscaler_tasks(org_id, args.sddc_id, args.ip_address)
        sys.exit(0)

    ret = get_instance_failure(args.sddc_id, org_id, region, vpc_id,
                               args.ip_address, args.instance_id,
                               args.no_console_output, args.time_period)
    if args.host_state:
        r = get_rts_host_state(args.sddc_id, args.ip_address)

    if ret['hardware_error']:
        RECOMMENDATION['Recommendation'] = 'FILE_AWS_TICKET'
        RECOMMENDATION['Details'] = 'Console logs indicate AWS hardware failure'
    elif ret['instance_status_failure'] and ret['system_status_failure']:
            if abs(ret['first_system_status_failure'] - ret['first_instance_status_failure']) < timedelta(minutes=10):
                RECOMMENDATION['Recommendation'] = 'FILE_AWS_TICKET'
                RECOMMENDATION['Details'] = ('System and instance failure happened within 10 minutes of each other. '
                                             'Check host state to verify if it got rebooted (Transient Issue)')
            elif ret['instance_status_failure']:
                RECOMMENDATION['Recommendation'] = 'FILE_PR'
                RECOMMENDATION['Details'] = 'Collect host and console logs and file a PR for investigation (Host PSOD)'
            else:
                RECOMMENDATION['Details'] = 'Unable to provide recommendation. Please check autoscaler remediation task details'
    elif ret['instance_status_failure']:
        RECOMMENDATION['Recommendation'] = 'FILE_PR'
        RECOMMENDATION['Details'] = 'Collect host and console logs and file a PR for investigation (Host PSOD)'
    else:
        RECOMMENDATION['Details'] = 'Unable to provide recommendation. Please check autoscaler remediation task details'

    print
    print_data(ret)
    print
    print("Recommendation:")
    print(json.dumps(RECOMMENDATION, indent=2, sort_keys=False))
