#!/usr/local/bin/python

import os
import sys
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
parser.add_argument('-S', '--sddc-id', required=True, help='SDDC ID of the instance')
parser.add_argument('-I', '--ip-address', help='IP Address of instance')
parser.add_argument('-i', '--instance-id', help='Instance ID of instance')
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
    return (resp.json()['org_id'], resp.json()['resource_config']['sddc_manifest']['esx_ami']['region'],
        resp.json()['resource_config']['vpc_info']['id'])

def get_instance_data(sddc_id, org_id, region, vpc_id, ip_addr, inst_id):
    token = get_api_token()
    headers = DEFAULT_HEADERS
    headers.update({'csp-auth-token': token})
    url = 'https://vmc.vmware.com/vmc/api/operator/aws/credentials?orgId={}'.format(org_id)
    resp = api_request(url, method='post', headers=headers)
    if resp.status_code < 200 or resp.status_code > 204:
        print("Unable to obtain AWS credentials for Org " + org_id + " and sddc ID " + sddc_id)
        return None
    session_token = resp.json()['aws_credentials']['session_token']
    access_key = resp.json()['aws_credentials']['awsaccess_key_id']
    secret_key = resp.json()['aws_credentials']['awssecret_key']
    ec2_resource = boto3.resource('ec2', aws_access_key_id=access_key,
                                  aws_secret_access_key=secret_key, region_name=region,
                                  aws_session_token=session_token)
    
    filters = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
    if ip_addr:
        filters.append({'Name': 'private-ip-address', 'Values': [ip_addr]})
    if inst_id:
        filters.append({'Name': 'instance-id', 'Values': [inst_id,]})

    r = ec2_resource.instances.filter(Filters=filters)
    for item in r:
        print(item.instance_id, item.instance_type, item.private_ip_address, item.state['Name'], str(item.launch_time))


if __name__ == '__main__':

    args = parser.parse_args()
    org_id, region, vpc_id = get_sddc_org_region(args.sddc_id)
    if not org_id:
        sys.exit(1)

    get_instance_data(args.sddc_id, org_id, region, vpc_id,
                      args.ip_address, args.instance_id)
