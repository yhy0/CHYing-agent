# Faktory Web Dashboard can lead to denial of service(DOS) via malicious user input

**GHSA**: GHSA-x4hh-vjm7-g2jv | **CVE**: CVE-2023-37279 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770, CWE-789

**Affected Packages**:
- **github.com/contribsys/faktory** (go): < 1.8.0

## Description

### Summary
Faktory web dashboard can suffer from denial of service by a crafted malicious url query param `days`.

### Details
The vulnerability is related to how the backend reads the `days` URL query parameter in the Faktory web dashboard. The value is used directly without any checks to create a string slice. If a very large value is provided, the backend server ends up using a significant amount of memory and causing it to crash.

### PoC
To reproduce this vulnerability, please follow these steps:

Start the Faktory Docker and limit memory usage to 512 megabytes for better demonstration:
```
$ docker run --rm -it -m 512m \
  -p 127.0.0.1:7419:7419 \
  -p 127.0.0.1:7420:7420 \
  contribsys/faktory:latest
``` 

Send the following request. The Faktory server will exit after a few seconds due to out of memory:

```
$ curl 'http://localhost:7420/?days=922337'
```

### Impact
**Server Availability**: The vulnerability can crash the Faktory server, affecting its availability.
**Denial of Service Risk**: Given that the Faktory web dashboard does not require authorization, any entity with internet access to the dashboard could potentially exploit this vulnerability. This unchecked access opens up the potential for a Denial of Service (DoS) attack, which could disrupt service availability without any conditional barriers to the attacker. 

