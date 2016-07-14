#!/usr/bin/env python

import argparse
import sys

import signal
# import the standard JSON parser
import json
#import requests
# import the REST library
#from restful_lib import Connection
from time import strftime,gmtime
#from odf.form import Password
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import requests.packages.urllib3


TEST_SUFFIX='NAGIOS-' +  strftime("%Y%m%d-%H%M%S",gmtime())
VALUE_ORIG='http://www.' + TEST_SUFFIX + '.com/1'
VALUE_AFTER='http://www.' + TEST_SUFFIX + '.com/2'
TOKEN_URI='/oauth2/token'

def handler(signum, stack):
    print "UNKNOWN: Timeout reached, exiting."
    sys.exit(3)

def getAccessToken():
    """Fetch access token from Unity"""
    #disable ssl warnings and trust the unity server
    requests.packages.urllib3.disable_warnings()
    
    client = BackendApplicationClient(client_id=username)
    client.prepare_request_body(scope=['USER_PROFILE','GENERATE_USER_CERTIFICATE'])
    oauth = OAuth2Session(client=client)
    token = oauth.fetch_token(token_url='https://unity.eudat-aai.fz-juelich.de:8443/oauth2/token', verify=False,client_id='argo',client_secret='test')
    j = json.dumps(token)
    k = json.loads(j)
    print "Acquired access token: "+k['access_token']

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='B2ACCESS login, query probe')
    req = parser.add_argument_group('required arguments')
    req.add_argument('-u', '--url', action='store', dest='url', required=True,
            help='baseuri of B2ACCESS to test')
    req.add_argument('-U', '--username', action='store', dest='username', required=True,
            help='B2ACCESS user')
    req.add_argument('-P', '--pass', action='store', dest='password', required=True,
            help='B2ACCESS password')
    req.add_argument('-t', '--timeout', action='store', dest='timeout',
            help='timeout')
    parser.add_argument('-d', '--debug', action='store_true', dest='debug',
            help='debug mode')

    param = parser.parse_args()

    base_url = param.url
    base_url = base_url+TOKEN_URI
    username = param.username
    password = param.password
    timeout = param.timeout

    if param.timeout and int(param.timeout) > 0 :
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(int(param.timeout))
        print "UNITY url: "+base_url
        print "username: "+username
        print "password: "+password
        print "Timeout: "+timeout
    
    getAccessToken()