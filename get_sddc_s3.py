#!/usr/bin/python

import json
import os
import sys
import requests
import boto3
from dateutil import parser
from datetime import datetime
from pprint import pprint
import urllib3

PROD_AUTH_URL = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize"

def get_api_token(url=PROD_AUTH_URL, token=None):
    if not token:
        token = os.environ.get("VMC_REFRESH_TOKEN", None)
    if not token:
        print("Please set your VMC_REFRESH_TOKEN environment variable. Quitting")
        return None
    resp = api_req(url, method='post', headers={'Content-type': 'application/x-www-form-urlencoded'},
                       data={'refresh_token': token})
    if resp.status_code < 200 or resp.status_code > 202:
        print("Unable to obtain access token from refresg token. Quitting")
        return None
    return resp.json()['access_token']

def api_req(url, token=None, method='get', headers=None, data=None, params=None):
    if not headers:
        headers = {'Accept': 'application/json', 'Content-type': 'application/json',
                   #'x-vmc-caller-role-info': 'caller-org-id=90d785a9-f5c9-41ce-92b6-5d501ae06810',
                   'csp-auth-token': token}
    if method == 'post':
        # req = requests.Request('POST', url, headers=headers, data=data, params=params)
        resp = requests.post(url, headers=headers, data=data, params=params)
    else:
        resp = requests.get(url, headers=headers, data=data, params=params)
    return resp

def main():
    sddc_id = sys.argv[1]
    token = get_api_token()
    url = 'https://vmc.vmware.com/vmc/api/operator/sddcs/{}'.format(sddc_id)
    resp = api_req(url, token)
    sddc = resp.json()
    sddc_name = sddc['name']
    org_id = sddc['org_id']
    linked_vpc = None
    # num_hosts = sddc['numHosts']
    if 'resource_config' in sddc and sddc['resource_config'] and 'nsx_reverse_proxy_url' in sddc['resource_config']:
        sddc_version = sddc['resource_config']['sddc_manifest']['vmc_version']
        nsx_rp = sddc['resource_config']['nsx_reverse_proxy_url']
        url = nsx_rp + 'orgs/' + org_id + '/sddcs/' + sddc_id + '/policy/api/v1/infra/linked-vpcs'
        resp = api_req(url, token)
        if resp.status_code == 200:
            # HACK: Always extract the first linked VPC entry
            results = resp.json()['results']
            linked_vpc = results[0]['linked_vpc_id']
            #print(linked_vpc)
            if linked_vpc:
                url = nsx_rp + 'orgs/' + org_id + '/sddcs/' + sddc_id + '/policy/api/v1/infra/linked-vpcs/' + linked_vpc + '/connected-services'
                resp = api_req(url, token)
                if resp.status_code == 200:
                    for item in resp.json()['results']:
                        print(item['name'] + ": " + str(item['enabled']))
                else:
                    print("Unable to determine S3 connectivity status for SDDC " + sddc_id)
        else:
            print("Unable to determine connected VPC for SDDC " + sddc_id)

if __name__ == '__main__':
    main()
