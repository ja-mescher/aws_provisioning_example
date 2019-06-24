import os
import json
import binascii
import socket
import argparse
import requests
from requests_aws4auth import AWS4Auth

ACCOUNTS_MANAGER_EVENT = 'masters-22073'
ACCOUNTS_MANAGER_USER_KEY_ID = 'AKIAJ5677V3VJDRM6TRQ'
ACCOUNTS_MANAGER_SECRET_KEY = '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'
ACCOUNTS_MANAGER_REGION = 'us-west-2'
ACCOUNTS_MANAGER_API_ID = 'cgqps0uf0f'
ACCOUNTS_MANAGER_STAGE = 'test'

def get_credentials(
        event,
        password,
        user,
        key_id=ACCOUNTS_MANAGER_USER_KEY_ID,
        secret_key=ACCOUNTS_MANAGER_SECRET_KEY,
        region=ACCOUNTS_MANAGER_REGION,
        stage=ACCOUNTS_MANAGER_STAGE,
        api_id=ACCOUNTS_MANAGER_API_ID):

    api_auth = AWS4Auth(key_id, secret_key, region, 'execute-api')
    api_url = 'https://{}.execute-api.{}.amazonaws.com/{}/get-credentials'.format(api_id, region, stage)
    api_data = {'event':event, 'password':password, 'user':user, 'system_data':{'hostname':socket.gethostname()}}
    response = requests.post(api_url, json=api_data, auth=api_auth)

    if response.status_code != 200:
        raise RuntimeError('API call to {} failed with status code {}: {}'.format(api_url, response.status_code, response.text))

    cred_response = json.loads(response.text)
    if 'error_msg' in cred_response:
        raise RuntimeError('API call to {} failed with error_msg: {}'.format(api_url, cred_response['error_msg']))
        
    return json.loads(response.text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get AWS credentials for event')
    parser.add_argument(
        '--event',
        dest='event',
        nargs='?',
        default=ACCOUNTS_MANAGER_EVENT,
        metavar='name',
        help='Event name (uses {} if omitted)'.format(ACCOUNTS_MANAGER_EVENT))
    parser.add_argument(
        '--password',
        dest='password',
        nargs='?',
        metavar='password',
        help='Event password')
    parser.add_argument(
        '--out',
        dest='out_filename',
        nargs='?',
        default='aws_credentials.txt',
        metavar='filename',
        help='Save credentials to the file (If omitted, aws_credentials.txt will be used)')
    args = parser.parse_args()

    id_filename = 'id.txt'
    id = ''
    if os.path.isfile(id_filename):
        # Load existing key
        with open(id_filename, 'r') as f:
            id = f.read()
    if len(id) < 4:
        with open(id_filename, 'w') as f:
            id = binascii.b2a_hex(os.urandom(16)).decode('ascii')
            f.write(id)

    credentials = get_credentials(event=args.event, password=args.password, user=id)

    credentials_str = '\n'.join([
        'AWS Account ID:    {}'.format(credentials['account_id']),
        'AWS Console URL:   {}'.format(credentials['console_url']),
        'Console Username:  {}'.format(credentials['user_name']),
        'Console Password:  {}'.format(credentials['user_password']),
        'Access Key ID:     {}'.format(credentials['access_key_id']),
        'Secret Access Key: {}'.format(credentials['secret_access_key'])])

    print(credentials_str)

    with open(args.out_filename, 'w') as f:
        f.write(credentials_str)
