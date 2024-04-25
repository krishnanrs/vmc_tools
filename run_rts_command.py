#!/usr/local/bin/python3

import os
import sys
import time
from datetime import datetime, timedelta, timezone
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
parser.add_argument('-C', '--command', required=True, help='RTS command to run')
parser.add_argument('-c', '--cluster', help='Cluster ID to query vsan resync status')
parser.add_argument('-t', '--ticket', help='Jira CSSD Ticket ID')
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

def get_rts_vsan_resync(sddc_id, command, cluster='None', ticket='None'):
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    url = 'https://internal.vmc.vmware.com/vmc/rts/api/operator/script'
    if ticket:
        reason = ticket
    else:
        reason = 'test'
    rts_script_data = "scriptId:{},sddc-id:{},reason:{}".format(command, sddc_id, reason)
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
            #print(output['result'])
            print(json.dumps(output['result']['output'], indent=2, sort_keys=False))
            #for host in output['result']['output']['esx']:
            #    print(json.dumps(host, indent=2, sort_keys=False))
            #print(resp.json()['params']['SCRIPTDATA']['data'])
            return 0
    print("Timed out waiting for RTS task to complete")
    return None


if __name__ == '__main__':

    args = parser.parse_args()
    get_rts_vsan_resync(args.sddc_id, args.command, args.cluster, args.ticket)
    sys.exit(0)
