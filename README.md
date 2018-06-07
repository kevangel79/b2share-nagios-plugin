# B2ACCESS Monitoring probe for ARGO

## Setting up environment
- The probe has been tested with Python version 2.7.x
- You may need to install (using pip) the following Python modules as they do not come with original distribution:
	- requests
	- oauthlib
	- validators
- As for the X.509 certificate based probing
	- the public and private keys should be in PEM format
	- should the private key encrypted with a passphrase, the value of **-t** flag should be sufficient enough to type in the secret (otherwise the prompt will disappear and the probe will fail), it is however recommended to not use the passphrase
- The probe is not compatible with Unity version earlier than 2.x.x, please use v0.3 for earlier version

## Overview
The B2ACCESS probe for ARGO does the following:

- Fetch access token using the OAuth 2.0 client credentials flow
- Validate the access token
- Fetch user information (via REST API)
  - on the basis of the access token,
  - while authenticating with username and password, and
  - X509 certificate based authentication

## Pre-requisites:

- Probe robot users SHOULD have two accounts registered within B2ACCESS/UNITY: username/password and X509 certificate, former are the OAuth/OIDC client credentials
- The probe users SHOULD be a part of the group **/oauth-clients** or the group defined for the property **unity.oauth2.as.clientsGroup** inside the **/UNITY-CONF/endpoints/oauth2-as.properties file**, additionally they SHOULD have **sys:oauth:allowedGrantFlows = client** attribute defined inside the group. The attribute can also be set by filling-up the OAuth client registration form
- The users SHOULD also be a part of the group defined for the property **unity.oauth2.as.usersGroup** inside the **/UNITY-CONF/endpoints/oauth2-as.properties file**
- Mandatory attributes such as email should be stored in root group of the B2ACCESS/UNITY instance 
- The UNITY administrator SHOULD enable certificate authenticator for the REST Admin endpoint (by default disabled) 

Example:
```
unityServer.core.endpoints.x.endpointType=RESTAdmin
unityServer.core.endpoints.x.endpointConfigurationFile=conf/authenticators/empty.json
unityServer.core.endpoints.x.contextPath=/rest-admin
unityServer.core.endpoints.x.endpointRealm=defaultRealm
unityServer.core.endpoints.x.endpointName=RESTful administration API
unityServer.core.endpoints.x.endpointAuthenticators=pwdRest;certRest
```

## How it works?

### Username & password based authentication

> python check_b2access.py -u [unity base url] -t [timeout in seconds] -V 1 -U [username] -P [password]

Example

> python check_b2access.py -u https://localhost:8443 -t 10 -V 1 -U argo -P testPass

### X.509 Certificate based authentication

> python check_b2access.py -u [unity base url] -t [timeout in seconds] -V 2 -C [Filesystem path to public key] -K [Filesystem path to private key]

Example

> python check_b2access.py -u https://localhost:8443 -t 10 -V 2 -C /Public_Key.pem -K Private_Key.pem


