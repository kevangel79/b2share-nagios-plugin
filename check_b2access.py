#!/usr/bin/env python

import argparse
import sys

import signal
import json
from time import strftime,gmtime
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import requests.packages.urllib3
import subprocess
import datetime

TEST_SUFFIX='NAGIOS-' +  strftime("%Y%m%d-%H%M%S",gmtime())
VALUE_ORIG='http://www.' + TEST_SUFFIX + '.com/1'
VALUE_AFTER='http://www.' + TEST_SUFFIX + '.com/2'
TOKEN_URI='/oauth2/token'

def handler(signum, stack):
    print "UNKNOWN: Timeout reached, exiting."
    sys.exit(3)

def getAccessToken(param):
    """Fetch access token from B2ACCESS"""
    if param.verbose == True:
        print "\nFetching access token from B2ACCESS"
    """ Pre-req: Create a user 'argo' with password 'test' in group 'oauth-clients' and 'eudat:b2share' or any other """ 
    
    try:
        client = BackendApplicationClient(client_id=username)
        client.prepare_request_body(scope=['USER_PROFILE','GENERATE_USER_CERTIFICATE'])
        oauth = OAuth2Session(client=client)
        token = oauth.fetch_token(token_url=str(param.url)+TOKEN_URI, verify=False,client_id=str(param.username),client_secret=str(param.password),scope=['USER_PROFILE','GENERATE_USER_CERTIFICATE'])
        j = json.dumps(token, indent=4)
        k = json.loads(j)
        print "Access token: "+k['access_token']
        
        getTokenInfo(str(param.url)+'/oauth2/tokeninfo', str(k['access_token']), param.verbose)
        getUserInfo(str(param.url)+'/oauth2/userinfo', str(k['access_token']), param.verbose)
    except:
        print("Error fetching OAuth 2.0 access token:", sys.exc_info()[0])
        raise
        sys.exit(1)
        
def getTokenInfo(url, token, verbose):
    """ Fetch access token details """
    try:
        if verbose:
            print "Fetching access token information from URL: "+url
            
        entity = requests.get(url,verify=False, headers = {'Authorization': 'Bearer '+token})
        j = entity.json()
        expire = datetime.datetime.fromtimestamp(int(j['exp'])).strftime('%Y-%m-%d %H:%M:%S')
        print "Expires in: "+expire
        
        if verbose:
            print 'Detailed token info: '+entity.text
    except:
        print("Error retrieving access token information:", sys.exc_info()[0])
        raise
        sys.exit(1)

def getUserInfo(url, token, verbose):
    """ Fetch user information using access token """
    try:
        print "\n"
        if verbose:
            print "Fetching user information based on access token, endpoint URL: "+url
        entity = requests.get(url,verify=False, headers = {'Authorization': 'Bearer '+token})
        j = entity.json()
        print "Subject: "+j['sub']
        print "Persistent Id: "+j['unity:persistent']
        
        if verbose:
            print 'Detailed user information: '+entity.text
        
    except:
        print("Error retrieving user information:", sys.exc_info()[0])
        raise
        sys.exit(1)

        
def getInfoUsernamePassword(param):
    """ Query user information with username and password """
    
    url = param.url+"/rest-admin/v1/resolve/userName/"+str(param.username)
    print "\n"
    if param.verbose:
        print "Query with username and password, endpoint URL: "+url
    
    try: 
        entity = requests.get(str(url),verify=False,auth=(str(param.username), str(param.password)))
        if entity.status_code == 403:
            print "Error occurred while resolving the given user: "+str(param.username)
            sys.exit(1)
        j = entity.json()
        print "Credential requirement: "+j['credentialInfo']['credentialRequirementId']
        print "Entity Id: "+str(j['id'])
        print "Username: "+j['identities'][0]['value']
        if param.verbose:
            print "Detailed user information: "+entity.text
        
    except:
        print("Error retrieving user information with username/password:", sys.exc_info()[0])
        raise
        sys.exit(1)
        
def getInfoCert(param):
    """ Query user information with X509 Certificate Authentication """
    
    
    try:
        cert_txt = subprocess.check_output(["openssl", "x509", "-subject", "-noout","-in", param.certificate])
    
        sub = str(cert_txt).replace("subject= ", "")
    
        dn = getLdapName(sub)
    
        """ url = param.url+"/rest-admin/v1/resolve/x500Name/CN=Ahmed Shiraz Memon,OU=IAS-JSC,OU=Forschungszentrum Juelich GmbH,O=GridGermany,C=DE" """
    
        url = param.url+"/rest-admin/v1/resolve/x500Name/"+dn
        
        print "\n"
        
        if param.verbose:
            print "Query user information with X509 Certificate Authentication, endpoint URL:" + url
        
        entity = requests.get(str(url),verify=False,cert=(str(param.certificate), str(param.key)))
        j = entity.json()
        print "Credential requirement: "+j['credentialInfo']['credentialRequirementId']
        print "Entity Id: "+str(j['id'])
        print "X500Name: "+j['identities'][0]['value']
        
        if entity.status_code == 403:
            print "Error occurred while resolving the given user: "+str(param.username)
            exit(1)
        if param.verbose:
            print "Detailed user information: "+entity.text
    except:
        print("Error retrieving user information by X509 certificate:", sys.exc_info()[0])
        raise
        sys.exit(1)

def getLdapName(openssl_name):
    name = str(openssl_name)
    strs = name.split("/")
    
    strs.reverse()
    
    strs[0] = str(strs[0]).rstrip()
    
    strs.pop()
    
    print strs
    
    str1 = ','.join(strs)
    
    return str1
    

if __name__ == '__main__':
    #disable ssl warnings and trust the unity server
    requests.packages.urllib3.disable_warnings()
    parser = argparse.ArgumentParser(description='B2ACCESS login, query probe')
    req = parser.add_argument_group('required arguments')
    req.add_argument('-u', '--url', action='store', dest='url', required=True,
            help='baseuri of B2ACCESS-UNITY to test')
    req.add_argument('-U', '--username', action='store', dest='username', required=True,
            help='B2ACCESS user')
    req.add_argument('-P', '--password', action='store', dest='password', required=True,
            help='B2ACCESS password')
    req.add_argument('-t', '--timeout', action='store', dest='timeout',
            help='timeout')
    req.add_argument('-v', '--version', action='store', dest='version',
            help='version')
    req.add_argument('-V', '--verbose', action='store_true', dest='verbose',
            help='increase output verbosity', default=False)
    parser.add_argument('-d', '--debug', action='store_true', dest='debug',
            help='debug mode')
    parser.add_argument('-C', '--cert', action='store', dest='certificate',
            help='Path to public key certificate')
    parser.add_argument('-K', '--key', action='store', dest='key',
            help='Path to private key')

    param = parser.parse_args()
    
    base_url = param.url
    username = param.username
    password = param.password
    timeout = param.timeout
    
    if param.verbose == True:
        print "verbosity is turned on"
    
    if param.timeout and int(param.timeout) > 0 :
        print "Timeout: "+timeout
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(int(param.timeout))
        
    print "Starting B2ACCESS Probe...\n---------------------------\n"
    print "B2ACCESS url: "+str(base_url)
    print "B2ACCESS username: "+username
    print "Public key: "+param.certificate   
    getAccessToken(param)
    getInfoUsernamePassword(param)
    getInfoCert(param)
    print "\nProbe exited gracefully!"
    sys.exit(0)