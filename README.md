# B2SHARE Monitoring probe for ARGO

## Setting up environment
This probe has been written for Python 3 and tested with Python 3.5.2
You may need to install (using e.g. `pip`) the following Python modules as 
they do not come with original distribution:
- requests
- jsonschema
- validators
- enum (in case lower than Python 3.4)

## Overview
The B2SHARE probe for ARGO does the following interaction 
with B2SHARE REST API:

- Search for records
- Fetch record's metadata from search results
- Fetch record's metadata schema
- Validate record's metadata agains record's metadata schema
- If a record with file is available, check that a file 
  should be able to be downloaded (HTTP HEAD request)

B2SHARE ARGO probe:
- makes HTTP requests (GET, HEAD) to B2SHARE's REST API
- parses JSON responses obtained from B2SHARE's REST API

## Pre-requisites:
- None

## How it works?

```
$ python check_b2share.py -h
usage: check_b2share.py [-h] -u URL [-t TIMEOUT] [-v] [--verify-tls]
                        [--error-if-no-records-present]

B2SHARE Nagios probe

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Base URL of B2SHARE instance to test.
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout of the test. Positive integer.
  -v, --verbose         Increase output verbosity
  --verify-tls          Should TLS certificate of B2SHARE server be verified
  --error-if-no-records-present
                        Should probe give an error if no records are present
                        at the B2SHARE instance.
```

Example

`$ python check_b2share.py -u https://b2share.eudat.eu:443 -t 15 -vv`

```
TLS certificate verification: OFF
Verbosity level: 2
Timeout: 15 seconds
B2SHARE URL: https://b2share.eudat.eu:443
Starting B2SHARE Probe...
---------------------------
Making a search.
Search returned some results.
A record containing files was found.
Fetching record's metadata schema.
Validating record's metadata schema.
Validating record against metadata schema.
Accessing file bucket of the record.
Fetching first file of the bucket.
---------------------------
OK, records, metadata schemas and files are accessible.
```

## Credits
This code is based on [EUDAT-B2ACCESS/b2access-probe](https://github.com/EUDAT-B2ACCESS/b2access-probe)
