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
parser.add_argument('-I', '--ip-address', help='IP Address of instance')
parser.add_argument('-n', '--host-name', help='Host name of instance')
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

def get_rts_host_state(sddc_id, ip_address, host_name):
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    url = 'https://internal.vmc.vmware.com/vmc/rts/api/operator/script'
    if ip_address:
        # rts_script_data = "scriptId:vcenter_host_manage,sddc-id:{},esx:{},action:state,reason:test".format(sddc_id, ip_address)
        rts_script_data = "scriptId:vcenter.get_host_state,sddc-id:{},esx:{},reason:test".format(sddc_id, ip_address)
    elif host_name:
        # rts_script_data = "scriptId:vcenter_host_manage,sddc-id:{},esx:{},action:state,reason:test".format(sddc_id, host_name)
        rts_script_data = "scriptId:vcenter.get_host_state,sddc-id:{},esx:{},reason:test".format(sddc_id, host_name)
    else:
        # rts_script_data = "scriptId:vcenter_host_manage,sddc-id:{},action:state,reason:test".format(sddc_id)
        rts_script_data = "scriptId:vcenter.get_host_state,sddc-id:{},filter_by_state:all,reason:test".format(sddc_id)
    data = {"requestBody": rts_script_data}
    resp = api_request(url, method='post', headers=headers, data=json.dumps(data))
    if resp.status_code < 200 or resp.status_code > 202:
        print("Unable to obtain host state from RTS for SDDC " + sddc_id + " and host " + ip_address)
        return None
    url = 'https://internal.vmc.vmware.com/vmc/rts/api/operator/tasks/{}'.format(resp.json()['id'])
    for i in range(0, 30):
        time.sleep(20)
        resp = api_request(url, headers=headers)
        if resp.status_code < 200 or resp.status_code > 202:
            print("Unable to obtain RTS task details")
            return None
        if resp.json()['status'] == 'FINISHED':
             output = json.loads(resp.json()['params']['SCRIPTDATA']['data'])
             # if len(output['output']['hosts']) > 0:
             if len(output['result']['output']['esx']) > 0:
                 print('Host', 'instanceId', 'connectionState', 'uptime (Days)')
             # for host in output['output']['hosts']:
             for host in output['result']['output']['esx']:
                 boottime = datetime.strptime(host['bootTime'], '%Y-%m-%d %H:%M:%S.%f+00:00')
                 conn = host['connectionState']
                 now = datetime.utcnow()
                 uptime = abs(now - boottime)
                # print(host['esx'], host['instance_id'], host['bootTime'])
                 print(host['name'], host['instance_id'], conn, uptime.days)
             return 0
    print("Timed out waiting for RTS task to complete")
    return None

if __name__ == '__main__':

    args = parser.parse_args()
    if args.ip_address and args.host_name:
        print("Please specify only one of host name or IP address to get details of the specific host in the SDDC")
        sys.exit(1)
    get_rts_host_state(args.sddc_id, args.ip_address, args.host_name)
