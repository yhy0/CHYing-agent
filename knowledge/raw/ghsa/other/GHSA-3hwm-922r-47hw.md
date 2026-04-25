# Stud42 vulnerable to denial of service

**GHSA**: GHSA-3hwm-922r-47hw | **CVE**: N/A | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **atomys.codes/stud42** (go): < 0.23.0

## Description

A security vulnerability has been identified in the GraphQL parser used by the API of s42.app. An attacker can overload the parser and cause the API pod to crash. With a bit of threading, the attacker can bring down the entire API, resulting in an unhealthy stream. This vulnerability can be exploited by sending a specially crafted request to the API with a large payload.

An attacker can exploit this vulnerability to cause a denial of service (DoS) attack on the s42.app API, resulting in unavailability of the API for legitimate users.
