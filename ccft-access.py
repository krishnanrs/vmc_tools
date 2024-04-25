# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# This resembles the access to AWS Customer Carbon Footprint Tool data
# from the AWS Billing Console. Hence it is not using an official AWS interface and
# might change at any time without notice and just stop working.

import os
import boto3
import requests
import argparse
import json
from urllib.parse import urlencode
from datetime import datetime

default_start_date = "2020-01-01"
default_end_date = "2023-01-01"
PROD_AUTH_URL = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize"
DEFAULT_HEADERS = {'Accept': 'application/json', 'Content-type': 'Application/json'}

parser = argparse.ArgumentParser(description=
    """Experimental retrieval of AWS Customer Carbon Footprint Tool console data.
    The data is queried for a closed interval from START_DATE to END_DATE (YYYY-MM-DD).
    The queried timeframe must be less than 36 months and not before 2020-01-01.""")
parser.add_argument('--start-date', '-s',
    type=lambda s: datetime.strptime(s, "%Y-%m-%d"),
    default=datetime.strptime(default_start_date, "%Y-%m-%d"),
    help="first month of the closed interval, default: %s" % default_start_date)
parser.add_argument('--end-date', '-e',
    type=lambda s: datetime.strptime(s, "%Y-%m-%d"),
    default=datetime.strptime(default_end_date, "%Y-%m-%d"),
    help="last month of the closed interval, default: %s" % default_end_date)
parser.add_argument('-O', '--org-id',
    required=True, help='VMC Org ID to retrieve Carbon Foorprint Information')

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

def get_aws_credentials(org_id):
    headers = DEFAULT_HEADERS
    token = get_api_token()
    headers.update({'csp-auth-token': token})
    url = 'https://vmc.vmware.com/vmc/api/operator/aws/credentials?orgId={}'.format(org_id)
    resp = api_request(url, method='post', headers=headers)
    if resp.status_code < 200 or resp.status_code > 204:
        print("Unable to obtain AWS credentials for Org " + org_id + " and sddc ID " + sddc_id)
        return None
    return resp.json()['aws_credentials']['session_token'], resp.json()['aws_credentials']['awsaccess_key_id'], resp.json()['aws_credentials']['awssecret_key'], resp.json()['aws_account_number']


args = parser.parse_args()
start_date=args.start_date.strftime("%Y-%m-%d")
end_date=args.end_date.strftime("%Y-%m-%d")

billing_region = 'us-east-1'

(session_token, access_key, secret_key, aws_id)= get_aws_credentials(args.org_id)

if session_token is None:
    # this is most likely an IAM or root user
    exit("You seem to run this with an IAM user. Assume an account's role instead.")

session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, aws_session_token=session_token, region_name=billing_region)

# Create a new session in which all cookies are set during login
s = requests.Session()

aws_federated_signin_endpoint = 'https://signin.aws.amazon.com/federation'

# Get SigninToken
signin_token_params = {
    "Action": "getSigninToken",
    "Session": {
        "sessionId": access_key,
        "sessionKey": secret_key,
        "sessionToken": session_token

    }
}
signin_token_url = "%s?%s" % (
    aws_federated_signin_endpoint, urlencode(signin_token_params))
signin_token_request = s.get(signin_token_url)
signin_token = json.loads(signin_token_request.text)['SigninToken']

# Create Login URL
login_params = {
    "Action": "login",
    "Destination": "https://console.aws.amazon.com/",
    "SigninToken": signin_token
}
login_url = "%s?%s" % (aws_federated_signin_endpoint, urlencode(login_params))

r = s.get(login_url)
r.raise_for_status()

# get the account id to include it in the response
account_id = session.client("sts").get_caller_identity()["Account"]

# grap the xsrf token once
r = s.get("https://console.aws.amazon.com/billing/home?state=hashArgs")
r.raise_for_status()
xsrf_token = r.headers["x-awsbc-xsrf-token"]

# call the proxy via POST
cft_request = {
    "headers": {
        "Content-Type": "application/json"
    },
    "path": "/get-carbon-footprint-summary",
    "method": "GET",
    "region": billing_region,
    "params": {
        "startDate": start_date,
        "endDate": end_date
    }
}
cft_headers = {
    "x-awsbc-xsrf-token": xsrf_token
}

r = s.post(
    "https://%s.console.aws.amazon.com/billing/rest/api-proxy/carbonfootprint" % (billing_region),
    data=json.dumps(cft_request),
    headers=cft_headers
)
r.raise_for_status()
emissions = r.json()

output = {
     "accountId": account_id,
     "query": {
        "queryDate": datetime.today().strftime("%Y-%m-%d"),
        "startDate": start_date,
        "endDate": end_date,
     },
     "emissions": emissions
}

print(json.dumps(output, indent=2, sort_keys=False))
