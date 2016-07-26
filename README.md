# B2ACCESS Monitoring probe for ARGO

## Overview
The B2ACCESS probe for ARGO does the following:

- Fetch access token using the OAuth 2.0 client credentials flow
- Validate the access token
- Fetch user information (via REST API)
  - on the basis of the access token,
  - while authenticating with username and password, and
  - X509 certificate based authentication

## Pre-requisites:

- Probe robot user SHOULD have two accounts registered within B2ACCESS/UNITY: username/password and X509 certificate
- She SHOULD be a part of the group **/oauth-clients** or the group defined for the property **unity.oauth2.as.clientsGroup** inside the **/UNITY-CONF/endpoints/oauth2-as.properties file**, additionally the user SHOULD have **sys:oauth:allowedGrantFlows = client** attribute defined inside the group. The attribute can also be set filling-up the OAuth client registration form
- She SHOULD also be a part of the group defined for the property **unity.oauth2.as.usersGroup** inside the **/UNITY-CONF/endpoints/oauth2-as.properties file**
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

> python check_b2access.py -U [username] -P [password] -u [unity base url] -t [timeout in seconds] -C [Filesystem path to public key] -K [Filesystem path to private key]


