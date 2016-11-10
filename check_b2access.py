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
from oauthlib.oauth2.rfc6749.errors import OAuth2Error, MissingTokenError
from requests.exceptions import ConnectionError, HTTPError
import os.path
import validators
from validators.utils import ValidationFailure

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
        if param.verbose:
            print "Access token: "+k['access_token']
        
        getTokenInfo(str(param.url)+'/oauth2/tokeninfo', str(k['access_token']), param.verbose)
        getUserInfo(str(param.url)+'/oauth2/userinfo', str(k['access_token']), param.verbose)
    except ConnectionError as e:
        print "CRITICAL: Invalid Unity URL: {0}".format(e)
        sys.exit(2)
    except MissingTokenError as e:
        print "CRITICAL: Invalid client Id and/or secret: {0}".format(e.description)
        sys.exit(2)
    except TypeError as e:
        print e
        sys.exit(2)
    except:
        print("CRITICAL: Error fetching OAuth 2.0 access token:", sys.exc_info()[0])
        sys.exit(2)
        raise
        
        
def getTokenInfo(url, token, verbose):
    """ Fetch access token details """
    try:
        if verbose:
            print "Fetching access token information from URL: "+url
        
        entity = requests.get(url,verify=False, headers = {'Authorization': 'Bearer '+token})
        j = entity.json()
        expire = datetime.datetime.fromtimestamp(int(j['exp'])).strftime('%Y-%m-%d %H:%M:%S')
        if verbose:
            print "Expires on: "+expire
            print 'Detailed token info: '+entity.text
    except KeyError as e:
        print "WARNING: Invalid key(s): {0}".format(e)
        sys.exit(1)
    except ValueError as e:
        print "CRITICAL: Invalid access token: {0}".format(e)
        sys.exit(2)
    except ConnectionError as e:
        print "CRITICAL: Invalid token endpoint URL: {0}".format(e)
        sys.exit(2)
    except:
        print("CRITICAL: Error retrieving access token information:", sys.exc_info()[0])
        sys.exit(2)
        raise
        

def getUserInfo(url, token, verbose):
    """ Fetch user information using access token """
    try:
        if param.verbose:
            print "\n"
            print "Fetching user information based on access token, endpoint URL: "+url
        entity = requests.get(url,verify=False, headers = {'Authorization': 'Bearer '+token})
        j = entity.json()
        if param.verbose:
            print "Subject: "+j['sub']
            print "Persistent Id: "+j['unity:persistent']
            print 'Detailed user information: '+entity.text
    except KeyError as e:
        print "WARNING: Invalid key(s): {0}".format(e)
        sys.exit(1)
    except ValueError as e:
        print "CRITICAL: Invalid access token: {0}".format(e)
        sys.exit(2)
    except ConnectionError as e:
        print "CRITICAL: Invalid UserInfo endpoint URL: {0}".format(e)
        sys.exit(2)  
    except:
        print("CRITICAL: Error retrieving user information:", sys.exc_info()[0])
        sys.exit(2)
        raise

        
def getInfoUsernamePassword(param):
    """ Query user information with username and password """
    
    url = param.url+"/rest-admin/v1/resolve/userName/"+str(param.username)
    
    if param.verbose:
        print "\nQuery with username and password, endpoint URL: "+url
    
    try: 
        uname = param.username
        pwd = param.password
        entity = requests.get(str(url),verify=False,auth=(uname, pwd))
        if entity.status_code == 403:
            raise HTTPError("CRITICAL: Error retrieving the user information with username {0}: invalid username/password".format(uname))
            sys.exit(2)
        j = entity.json()
        if param.verbose:
            print "Credential requirement: "+j['credentialInfo']['credentialRequirementId']
            print "Entity Id: "+str(j['id'])
            print "Username: "+j['identities'][0]['value']
            print "Detailed user information: "+entity.text
    except ConnectionError as e:
        print "CRITICAL: Invalid Unity endpoint URL: {0}".format(e)
        sys.exit(2)
    except HTTPError as e:
        print e
        sys.exit(2)
    except KeyError as e:
        print "CRITICAL: Invalid key(s): {0}".format(e)
        sys.exit(2)   
    except:
        print("CRITICAL: Error retrieving user information with the username/password:", sys.exc_info()[0])
        sys.exit(2)
        raise
        
def getInfoCert(param):
    """ Query user information with X509 Certificate Authentication """
    try:
        cert_txt = subprocess.check_output(["openssl", "x509", "-subject", "-noout","-in", param.certificate])
    
        sub = str(cert_txt).replace("subject= ", "")
    
        dn = getLdapName(sub)
    
        """ url = param.url+"/rest-admin/v1/resolve/x500Name/CN=Ahmed Shiraz Memon,OU=IAS-JSC,OU=Forschungszentrum Juelich GmbH,O=GridGermany,C=DE" """
    
        url = param.url+"/rest-admin/v1/resolve/x500Name/"+dn
        
        if param.verbose:
            print "\nQuery user information with X509 Certificate Authentication, endpoint URL:" + url
        
        entity = requests.get(str(url),verify=False,cert=(str(param.certificate), str(param.key)))
        
        if (entity.status_code == 400) or (entity.status_code == 403):
            raise HTTPError("CRITICAL: Error retrieving the user information with X500Name {0}: invalid certificate".format(dn))
            sys.exit(2)
        
        j = entity.json()
        if param.verbose:
            print "Credential requirement: "+j['credentialInfo']['credentialRequirementId']
            print "Entity Id: "+str(j['id'])
            print "X500Name: "+j['identities'][0]['value']
        
        if param.verbose:
            print "Detailed user information: "+entity.text
    except HTTPError as e:
        print e
        sys.exit(2)
    except KeyError as e:
        print "CRITICAL: Invalid key(s): {0}".format(e)
        sys.exit(2)
    except:
        print("CRITICAL: Error retrieving user information by X509 certificate:", sys.exc_info()[0])
        sys.exit(2)
        raise

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
    
    # req = parser.add_argument_group('required arguments')
    
    subParsers = parser.add_subparsers()
    
    parser.add_argument('-u', '--url', action='store', dest='url', required=True,
             help='baseuri of B2ACCESS-UNITY to test')
    parser.add_argument('-t', '--timeout', action='store', dest='timeout',
             help='timeout')
    parser.add_argument('-v', '--version', action='store', dest='version',
             help='version')
    parser.add_argument('-V', '--verbose', action='store_true', dest='verbose',
             help='increase output verbosity', default=False)
    parser.add_argument('-d', '--debug', action='store_true', dest='debug',
             help='debug mode')
    
    u_parser = subParsers.add_parser('1',help='Username/Password based authentication')
    u_parser.add_argument('-U', '--username', action='store', dest='username', required=True,
             help='B2ACCESS user')
    u_parser.add_argument('-P', '--password', action='store', dest='password', required=True,
             help='B2ACCESS password')
    u_parser.set_defaults(action='1')
    
    c_parser = subParsers.add_parser('2',help='X.509 Certificate based authentication')
    c_parser.add_argument('-C', '--cert', action='store', dest='certificate',
            help='Path to public key certificate', required=True)
    c_parser.add_argument('-K', '--key', action='store', dest='key',
             help='Path to private key', required=True)    
    c_parser.set_defaults(action='2')
    
    param = parser.parse_args()
    base_url = param.url
    timeout = param.timeout
    
    if param.action == "1":
        username = param.username
        password = param.password
    
    
    if param.verbose == True:
        print "verbosity is turned ON"
    
    if param.timeout and int(param.timeout) > 0 :
        print "Timeout: "+timeout
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(int(param.timeout))

    
    
    if param.verbose:    
        print "Starting B2ACCESS Probe...\n---------------------------\n"
        print "B2ACCESS url: "+str(base_url)
        if param.action == "1":
            print "B2ACCESS username: "+username
        if param.action == "2":
            print "Public key: "+param.certificate
    
    try:   
        if param.action == "2":
            if not os.path.exists(param.certificate):
                raise IOError("CRITICAL: Public key certificate file does not exist: {0}".format(param.certificate))
            if not os.path.exists(param.key):
                raise IOError("CRITICAL: Private key file does not exist: : {0}".format(param.key))
        if not validators.url(param.url):
            raise SyntaxError("CRITICAL: Invalid URL syntax {0}".format(param.url))
    except IOError as e:
        print e
        sys.exit(2)
    except SyntaxError as e:
        print e
        sys.exit(2)
    except:
        print(sys.exc_info()[0])
        sys.exit(2)
        raise
    
    if param.action == "1":
        getAccessToken(param)
        getInfoUsernamePassword(param)
    
    if param.action == "2":
        getInfoCert(param)
    
    if param.verbose:
        if param.action == "1":
            print "\nOK, User access token retrieval and login with username/password was successful" 
        if param.action == "2":
            print "\nOK, User login with X.509 Certificate was successful" 
    else:
        print "OK"
    sys.exit(0)