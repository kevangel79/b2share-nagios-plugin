# B2ACCESS monitoring probe

## Overview
The B2ACCESS probe for ARGO does the following:

- Fetch access token using the OAuth 2.0 client credentials flow
- Validate the access token
- Fetch user information 
..- on the basis of the access token,
..- while authenticating with username and password, and
..- X509 certificate

## Usage
> python check_b2access.py -U [username] -P [password] -u [unity base url] -t [timeout in seconds] -C [Filesystem path to public key] -K [Filesystem path to private key]

