# Keycloak Gatekeeper vulnerable to bypass on using lower case HTTP headers

**GHSA**: GHSA-jh6m-3pqw-242h | **CVE**: CVE-2020-14359 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-305

**Affected Packages**:
- **github.com/keycloak/keycloak-gatekeeper** (go): <= 1.2.8

## Description

A vulnerability was found in all versions of the deprecated package Keycloak Gatekeeper, where on using lower case HTTP headers (via cURL) we can bypass our Gatekeeper. Lower case headers are also accepted by some webservers (e.g. Jetty). This means there is no protection when we put a Gatekeeper in front of a Jetty server and use lowercase headers.
