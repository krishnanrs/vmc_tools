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
parser.add_argument('-i', '--instance-id', required=True, help='Instance ID of affected instance')
parser.add_argument('-a', '--account-id', required=True, help='AWS account ID of affected instance')
parser.add_argument('-c', '--cssd-id', help='Reference CSSD ID for the planned maintenance')
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

def rts_trigger_planned_maintenance(instance_id, account_id, cssd):
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    desc = 'Instance%20is%20running%20on%20degraded%20hardware'
    # Trigger planned maintenance with a start time 10 days from now
    start_time = datetime.now() + timedelta(days=10)
    url = 'https://internal.vmc.vmware.com/vmc/rts/api/operator/saasscript'
    rts_script_data = "scriptId:vmc.post_vmc_planned_maintenance,instance_id:{},account_id:{},start_time:{},description:{},reason:{}".format(instance_id,account_id,start_time.strftime("%m-%d-%Y%%20%H%%3A%M%%3A%S%%20UTC"),desc,cssd)
    data = {"requestBody": rts_script_data}
    resp = api_request(url, method='post', headers=headers, data=json.dumps(data))
    if resp.status_code < 200 or resp.status_code > 202:
        print("Unable to trigger planned maintenance for " + instance_id + " in shadow account  " + account_id)
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
            print(output['result'])
            #for host in output['result']['output']['esx']:
            #    print(json.dumps(host, indent=2, sort_keys=False))
            #print(resp.json()['params']['SCRIPTDATA']['data'])
            return 0
    print("Timed out waiting for RTS task to complete")
    return None


if __name__ == '__main__':

    args = parser.parse_args()
    if not args.cssd_id:
        cssd = 'test'
    else:
        cssd = args.cssd_id

    ret = rts_trigger_planned_maintenance(args.instance_id, args.account_id, cssd)
