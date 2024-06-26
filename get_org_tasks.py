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
parser.add_argument('-O', '--org-id', required=True, help='Org ID to query the tasks')
parser.add_argument('-t', '--task-type', required=False, help='VMC Task Type', default='All')
parser.add_argument('-s', '--task-status', required=False, help='VMC Task Status', default='All')
parser.add_argument('-i', '--task-id', required=False, help='Get specific VMC taskID and exit')
parser.add_argument('-p', '--time-period', type=int, choices=[1,3,7,15,30,60,180,360,720,1440], default=3,
                    help='Time range in days to retrieve SDDC tasks')
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

def get_task(task_id):
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    url = 'https://vmc.vmware.com/vmc/api/operator/tasks/{}'.format(task_id)
    res = api_request(url, headers=headers)
    print(json.dumps(res.json(), indent=2, sort_keys=False))

def fetch_org_tasks(org_id, time_period=3, task_type='All', task_status='All'):
    filter_time = datetime.utcnow() - timedelta(days=time_period)
    filter_param = "created gt {}z and org_id eq {}".format(filter_time.isoformat(), org_id)
    if task_type != 'All':
        filter_param += " and task_type eq '{}'".format(task_type)
    if task_status != 'All':
        filter_param += " and status eq '{}'".format(task_status)
    url = 'https://vmc.vmware.com/vmc/api/operator/tasks'
    filter_param_string = "({})".format(filter_param)
    params = {'$filter': filter_param_string}
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    res = api_request(url, headers=headers, params=params)
    print(json.dumps(res.json(), indent=2, sort_keys=False))


if __name__ == '__main__':

    args = parser.parse_args()

    if args.task_id:
        ret = get_task(args.task_id)
    else:
        #ret = fetch_sddc_tasks(args.sddc_id, org_id, args.time_period, task_type=NULL, task_status=NULL)
        ret = fetch_org_tasks(args.org_id, args.time_period, task_type=args.task_type, task_status=args.task_status)
