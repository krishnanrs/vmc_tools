#!/usr/local/bin/python3

import os
import sys
import time
from datetime import datetime, timedelta, timezone
import requests
import argparse
import json
import re
from pprint import pprint
from argparse import RawTextHelpFormatter
import  boto3
from botocore.exceptions import ClientError

PROD_AUTH_URL = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize"
RECOMMENDATION = {'Recommendation': None, 'Details': None}
DEFAULT_HEADERS = {'Accept': 'application/json', 'Content-type': 'Application/json'}
LINT_API_URL = "https://api.mgmt.cloud.vmware.com"
LINT_EU_API_URL = "https://de.api.mgmt.cloud.vmware.com"
LINT_AU_API_URL = "https://au.api.mgmt.cloud.vmware.com"
LINT_LOG_QUERY_LINK = "/ops/query/log-query-tasks"
DISABLE_RECURSIVE = False
ROWS = 100000

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
parser.add_argument('-c', '--cloud-trail', action='store_true',
                    help='Query the cloudtrail for host reboot events')
parser.add_argument('-q', '--lint-query', action='store_true',
                    help='Query the LINT logs for VM HA restart events')
parser.add_argument('-u', '--uslint-query', action='store_true',
                    help='Query the LINT logs for VM HA restart events')
parser.add_argument('-r', '--nic-reset-query', action='store_true',
                    help='Query the LINT logs for NIC reset events')
parser.add_argument('-l', '--log-bundle', help='Reference ID for collecting host log bundle')
parser.add_argument('-p', '--time-period', type=int, choices=[1,3,6,12,24,36,48,72,168], default=3,
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
        print(resp.text)
        print("Unable to obtain access token from refresh token. Quitting")
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
    # return (resp.json()['org_id'], resp.json()['resource_config']['sddc_manifest']['esx_ami']['region'],
    return (resp.json()['org_id'], resp.json()['resource_config']['sddc_manifest']['esx_nsxt_ami']['region'],
        resp.json()['resource_config']['vpc_info']['id'])

def get_autoscaler_tasks(org_id, sddc_id, ip_address):
    token = get_api_token()
    #url = 'https://vmc.vmware.com/vmc/autoscaler/api/orgs/{}/sddcs/{}/get-tasks'.format(org_id, sddc_id)
    #url = 'https://vmc.vmware.com/vmc/autoscaler/api/orgs/{}/sddcs/{}/get-tasks?from=2022-01-01'.format(org_id, sddc_id)
    url = 'https://vmc.vmware.com/vmc/autoscaler/api/orgs/{}/sddcs/{}/get-tasks?from=2024-01-01'.format(org_id, sddc_id)
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    resp = api_request(url, headers=headers)
    if resp.status_code < 200 or resp.status_code > 202:
        print("Unable to obtain autoscaler tasks for SDDC with ID " + sddc_id + ". Quitting...")
        return None
    for sddc_task in resp.json()['sddc_task_status']:
        if 'cluster_task_status' in sddc_task:
            for cluster_task in sddc_task['cluster_task_status']:
                #url = 'https://vmc.vmware.com/vmc/autoscaler/api/operator/tasks/{}'.format(cluster_task['task_id'])
                #r = api_request(url, headers=headers)
                #print(json.dumps(r.json(), indent=2, sort_keys=False))
                #continue

                if ip_address and cluster_task['hostname'] == ip_address:
                    url = 'https://vmc.vmware.com/vmc/autoscaler/api/operator/tasks/{}'.format(cluster_task['task_id'])
                    r = api_request(url, headers=headers)
                    print(json.dumps(r.json(), indent=2, sort_keys=False))
                    if r.json()['task_type'] == 'REMEDIATE-EBS-HOST' and 'replaceEbsHostTaskId' in r.json()['params']:
                        replace_ebs_task = None
                        replace_ebs_task = r.json()['params']['replaceEbsHostTaskId']
                        if replace_ebs_task:
                            url = 'https://vmc.vmware.com/vmc/autoscaler/api/operator/tasks/{}'.format(replace_ebs_task)
                            r = api_request(url, headers=headers)
                            print(json.dumps(r.json(), indent=2, sort_keys=False))
                # else:
                #     for cluster_task in sddc_task['cluster_task_status']:
                #         print(cluster_task)
        # else:
        #     print(resp.json())

def get_rts_host_state(sddc_id, ip_address):
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    url = 'https://internal.vmc.vmware.com/vmc/rts/api/operator/script'
    rts_script_data = "scriptId:vcenter.get_host_state,sddc-id:{},esx:{},reason:test".format(sddc_id, ip_address)
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
            # print(output['result'])
            for host in output['result']['output']['esx']:
                print(json.dumps(host, indent=2, sort_keys=False))
            #print(resp.json()['params']['SCRIPTDATA']['data'])
            return 0
    print("Timed out waiting for RTS task to complete")
    return None

def get_rts_log_bundle(sddc_id, ip_address, ref_id):
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    #url = 'https://internal.vmc.vmware.com/vmc/rts/api/user/logbundle/collect'
    # url = 'https://internal.vmc.vmware.com/vmc/rts/api/operator/script'
    url = 'https://internal.vmc.vmware.com/vmc/rts/api/user/sddc/{}/logbundle/esx'.format(sddc_id)
    now = datetime.now()
    # rts_script_data = "scriptId:esx_support_s3,sddc-id:{},timestamp:{},resource_type:host,host:{},referenceid:{},log_access_reason:No Access to Log Intelligence,reason:{}".format(sddc_id, now.strftime("%Y-%m-%d-%H:%M"), ip_address,ref_id, ref_id)
    # rts_script_data = "scriptId:esx.collect_support_bundle,sddc-id:{},resource_type:host,host:{},performance:false,reason:{}".format(sddc_id, ip_address, ref_id)
    # data = {"requestBody": rts_script_data}
    data = {"resource_type": "host", "host": ip_address, "reason": ref_id, "performance": "false"}
    resp = api_request(url, method='post', headers=headers, data=json.dumps(data))
    if resp.status_code < 200 or resp.status_code > 202:
        print("Unable to trigger log bundle collection for host " + ip_address + " in SDDC " + sddc_id)
        return None
    else:
        print("Successfully triggered log bundle collection for host " + ip_address + " in SDDC " + sddc_id)
        url = 'https://internal.vmc.vmware.com/vmc/rts/api/operator/tasks/{}'.format(resp.json()['id'])
        for i in range(0, 2):
            time.sleep(20)
            resp = api_request(url, headers=headers)
            if resp.status_code < 200 or resp.status_code > 202:
                print("Unable to obtain RTS task details")
                return None
            if resp.json()['status'] == 'FAILED':
                print("Log bundle collection failed. Please check the host name or retry after some time")
                break
        return 0

def get_lint_log_query_results(url, headers, base_url):
    result_list = list()
    waiting = True
    while waiting:
        # print(url)
        time.sleep(10)

        resp = api_request(url, headers=headers)
        if resp.json()['taskInfo']['stage'] == 'FAILED':
            raise AssertionError(http_result_dict['failureMessage'])
        elif resp.json()['taskInfo']['stage'] == 'FINISHED':
            result_list = resp.json()['logQueryResults']
            if resp.json().get('nextPageLink') and not DISABLE_RECURSIVE:
                # result_list = result_list + get_lint_log_query_results(LINT_API_URL + resp.json()['nextPageLink'], headers)
                result_list = result_list + get_lint_log_query_results(base_url + resp.json()['nextPageLink'], headers, base_url)
            waiting = False


    return result_list


def lint_query(sddc_id, region, time_period=3, uslint_query=False, nic_reset=False):
    if nic_reset:
        LOG_QUERY = "SELECT log_timestamp, text FROM logs WHERE (text='vmnic0' AND text = 'reset' AND text != 'logical space' AND text != 'Function reset' AND sddc_id='{}') ORDER BY timestamp ASC".format(sddc_id)
    else:
        TEXT = "vsphere HA restarted virtual machine"
        LOG_QUERY = "SELECT log_timestamp, text FROM logs WHERE (text='{}' AND sddc_id='{}') ORDER BY timestamp ASC".format(TEXT, sddc_id)
    now = datetime.now()
    END_TIME = round(now.timestamp() * 1000)
    START_TIME = round((now - timedelta(hours=time_period)).timestamp() * 1000)
    QUERY_DICT = {
        "logQuery": LOG_QUERY,
        "start": START_TIME,
        "end": END_TIME,
        "rows": ROWS
    }

    if uslint_query:
        lint_api_url = LINT_API_URL
        headers = DEFAULT_HEADERS
        token = get_api_token()
        headers.update({'csp-auth-token': token})
    elif region == 'ap-southeast-2':
        lint_api_url = LINT_AU_API_URL
        headers = DEFAULT_HEADERS
        token = get_api_token(token=os.environ.get("VMC_AU_REFRESH_TOKEN", None))
        headers.update({'csp-auth-token': token})
    elif region == 'eu-central-1' or region == 'eu-west-2' or region == 'eu-west-1':
        lint_api_url = LINT_EU_API_URL
        headers = DEFAULT_HEADERS
        token = get_api_token(token=os.environ.get("VMC_FRA_REFRESH_TOKEN", None))
        headers.update({'csp-auth-token': token})
    else:
        lint_api_url = LINT_API_URL
        headers = DEFAULT_HEADERS
        token = get_api_token()
        headers.update({'csp-auth-token': token})

    # Start a query.
    # resp = api_request(LINT_API_URL + LINT_LOG_QUERY_LINK, method='post', headers=headers, data=json.dumps(QUERY_DICT))
    resp = api_request(lint_api_url + LINT_LOG_QUERY_LINK, method='post', headers=headers, data=json.dumps(QUERY_DICT))
    result = json.loads(resp.text)
    #print(result)
    if result.get('failureMessage', 0):
        raise AssertionError(result['failureMessage'])

    # Get the query.
    print("Sleeping for 30 seconds and start fetching log query results.")
    time.sleep(30)
    # result = get_lint_log_query_results(LINT_API_URL + result['documentSelfLink'], headers=headers)
    result = get_lint_log_query_results(lint_api_url + result['documentSelfLink'], headers=headers, base_url=lint_api_url)
    print(str(len(result)) + " items found")
    for item in result:
        print(item['text'])

    # Delete the task
    print("Delete LINT log query task.")
    # res = api_request(LINT_API_URL + LINT_LOG_QUERY_LINK + '/' + resp.json()['id'], method='delete', headers=headers)
    res = api_request(lint_api_url + LINT_LOG_QUERY_LINK + '/' + resp.json()['id'], method='delete', headers=headers)
    if res.status_code != 200 and res.status_code != 500:
        raise AssertionError
  
    return 0

def get_instance_failure(sddc_id, org_id, region, vpc_id, ip_addr, inst_id, no_console_logs=True, time_period=3, cloud_trail=False):
    instance_id = None
    hardware_failure = False
    instance_status_failure = False
    system_status_failure = False
    first_instance_status_failure = None
    first_system_status_failure = None
    last_instance_status_failure = None
    last_system_status_failure = None
    shadow_account_id = None
    period = 60
    cloudtrail_events = []
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
    aws_id = resp.json()['aws_account_number']
    if aws_id:
        shadow_account_id = aws_id
    failure_data['shadow_account_id'] = shadow_account_id
    ec2_client = boto3.client('ec2', aws_access_key_id=access_key,
                          aws_secret_access_key=secret_key, region_name=region,
                          aws_session_token=session_token)
    ec2_resource = boto3.resource('ec2', aws_access_key_id=access_key,
                                  aws_secret_access_key=secret_key, region_name=region,
                                  aws_session_token=session_token)
    cloudtrail = boto3.client('cloudtrail', aws_access_key_id=access_key,
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
            failure_data['availability_zone'] = item.placement['AvailabilityZone']
        if not instance_id:
            # Instance with matching IP was not found. Display autoscaler tasks and exit
            get_autoscaler_tasks(org_id, sddc_id, ip_addr)
            print('')
            #return failure_data 
            if not inst_id:
                pprint(failure_data)
                sys.exit(1)
    elif inst_id:
        failure_data['instance_id'] = inst_id
        filters = [{'Name': 'instance-id', 'Values': [inst_id]}, {'Name': 'vpc-id', 'Values': [vpc_id]}]
        r = ec2_resource.instances.filter(Filters=filters)
        for item in r:
            failure_data['ip_address'] = item.private_ip_address
            failure_data['instance_type'] = item.instance_type
            failure_data['instance_state'] = item.state
            failure_data['launch_time'] = item.launch_time
            failure_data['availability_zone'] = item.placement['AvailabilityZone']
        instance_id = inst_id

    if instance_id:
        if not no_console_logs:
            try:
                resp = ec2_client.get_console_output(InstanceId=instance_id, Latest=True)
                value = resp.get('Output', 'No Serial Logs available')
                if 'Hardware Error' in value or 'hardware vendor' in value:
                    hardware_failure = True
                home = os.path.expanduser("~")
                filename = os.path.join(home, instance_id + '-console.txt')
                with open(filename, 'wb') as f:
                    f.write(value.encode('utf-8'))
                print("Saving console output to file: " + filename)
                if value == 'No Serial Logs available' or len(value) == 0:
                    print("Console logs are empty")
                else:
                    r = re.compile("\d{4}-\d{2}-\d{1,2}T\d{2}:\d{2}\:\d{2}.\d{3}Z")
                    matches = r.findall(value)
                    #print(matches[-1])
                    if matches:
                        last_log = matches[-1]
                        now = datetime.now()
                        last_log_timestamp =  datetime.strptime(last_log, '%Y-%m-%dT%H:%M:%S.%fZ')
                        if abs(now - last_log_timestamp) > timedelta(days=3):
                            print("Console logs are old/stale")
            except ClientError as e:
                # print(e.message)
                print("%s" % e.response['Error'])
                pass

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
            # print(e.message)
            print("%s" % e.response['Error'])
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
            # print(e.message)
            print("%s" % e.response['Error'])
            pass

    if time_period > 24:
        period = 300
    elif time_period > 72:
        period = 3600
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

    if cloud_trail:
        resp = cloudtrail.lookup_events(
                   LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'RebootInstances'}],
                   StartTime=datetime.utcnow() - timedelta(hours=time_period),
                   EndTime=datetime.utcnow(),
                   MaxResults=100)
        # print("Reboot Events:", resp['Events'])
        for item in resp['Events']:
            print(item['CloudTrailEvent'])
            ctevent = json.loads(item['CloudTrailEvent'])
            if instance_id and instance_id ==  ctevent['requestParameters']['instancesSet']['items'][0]['instanceId']:
                cloudtrail_events.append({'instanceId': ctevent['requestParameters']['instancesSet']['items'][0]['instanceId'], 'eventTime': ctevent['eventTime']})
            if not instance_id:
                cloudtrail_events.append({'instanceId': ctevent['requestParameters']['instancesSet']['items'][0]['instanceId'], 'eventTime': ctevent['eventTime']})
        
    
    failure_data['instance_status_failure'] = instance_status_failure
    failure_data['system_status_failure'] = system_status_failure
    failure_data['first_instance_status_failure'] = first_instance_status_failure
    failure_data['first_system_status_failure'] = first_system_status_failure
    failure_data['last_instance_status_failure'] = last_instance_status_failure
    failure_data['last_system_status_failure'] = last_system_status_failure
    failure_data['hardware_error'] = hardware_failure
    if len(cloudtrail_events) > 0:
        failure_data['cloudtrail_events'] = cloudtrail_events
    return failure_data

def print_data(data):
    if data['first_instance_status_failure']:
        data['first_instance_status_failure'] = str(data['first_instance_status_failure'])
    if data['first_system_status_failure']:
        data['first_system_status_failure'] = str(data['first_system_status_failure'])
    if data['last_instance_status_failure']:
        data['last_instance_status_failure'] = str(data['last_instance_status_failure'])
    if data['last_system_status_failure']:
        data['last_system_status_failure'] = str(data['last_system_status_failure'])
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
    try:
        org_id, region, vpc_id = get_sddc_org_region(args.sddc_id)
        if not org_id:
            sys.exit(1)
    except ValueError:
        print("Unable to obtain SDDC details. Please check if sddcID is valid or if it has been deleted")
        sys.exit(1)

    # To collect log bundle
   
    if args.autoscaler_tasks:
        get_autoscaler_tasks(org_id, args.sddc_id, args.ip_address)
        sys.exit(0)

    if args.lint_query:
        lint_query(args.sddc_id, region, args.time_period, args.uslint_query)
        sys.exit(0)

    if args.nic_reset_query:
        lint_query(args.sddc_id, region, args.time_period, args.uslint_query, nic_reset=True)
        sys.exit(0)

    if args.log_bundle:
        get_rts_log_bundle(args.sddc_id, args.ip_address, args.log_bundle)
        sys.exit(0)

    ret = get_instance_failure(args.sddc_id, org_id, region, vpc_id,
                               args.ip_address, args.instance_id,
                               args.no_console_output, args.time_period, args.cloud_trail)
    if args.host_state:
        r = get_rts_host_state(args.sddc_id, args.ip_address)

    if 'instance_type' in ret and 'i3en.metal' in ret['instance_type']:
        launch_delta = 20
    else:
        launch_delta = 10

    if ret['hardware_error']:
        RECOMMENDATION['Recommendation'] = 'FILE_AWS_TICKET'
        RECOMMENDATION['Details'] = 'Console logs indicate AWS hardware failure'
    elif ret['instance_status_failure'] and ret['system_status_failure']:
            if 'launch_time' in ret and abs(ret['last_instance_status_failure'] - ret['launch_time']) < timedelta(minutes=launch_delta):
                RECOMMENDATION['Recommendation'] = 'FALSE_ALERT'
                RECOMMENDATION['Details'] = ('False alert on a newly launched instance')
            elif abs(ret['first_system_status_failure'] - ret['first_instance_status_failure']) < timedelta(minutes=10):
                if 'cloudtrail_events' in ret and len(ret['cloudtrail_events']) > 0:
                    for item in ret['cloudtrail_events']:
                        reboot_time = datetime.strptime(item['eventTime'],'%Y-%m-%dT%H:%M:%SZ')
                        reboot_time = reboot_time.replace(tzinfo=timezone.utc)
                        if item['instanceId'] == ret['instance_id'] and abs(reboot_time - ret['first_system_status_failure']) < timedelta(minutes=10):
                            RECOMMENDATION['Recommendation'] = 'HOST_REBOOT'
                            RECOMMENDATION['Details'] = ('System and instance failure happened within 10 minutes of each other. '
                                                         'However it appears that the host was rebooted via AWS.')
                            break
                if not RECOMMENDATION['Recommendation']:
                    RECOMMENDATION['Recommendation'] = 'FILE_AWS_TICKET'
                    if 'system_status' in ret and ret['system_status'][0]['Status'] == 'passed':
                        RECOMMENDATION['Details'] = ('System and instance failure happened within 10 minutes of each other. '
                                                     'Check host state to verify if it got rebooted (Transient Issue)')
                    else:
                        RECOMMENDATION['Details'] = ('Host went down due to an AWS failure (and is still down).')
            elif ret['instance_status_failure']:
                RECOMMENDATION['Recommendation'] = 'FILE_PR'
                RECOMMENDATION['Details'] = 'Collect host and console logs and file a PR for investigation (Host PSOD)'
            else:
                RECOMMENDATION['Details'] = 'Unable to provide recommendation. Please check autoscaler remediation task details'
    elif ret['instance_status_failure'] and 'launch_time' in ret and \
        abs(ret['last_instance_status_failure'] - ret['launch_time']) < timedelta(minutes=launch_delta):
        RECOMMENDATION['Recommendation'] = 'FALSE_ALERT'
        RECOMMENDATION['Details'] = ('False alert on a newly launched instance')
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
