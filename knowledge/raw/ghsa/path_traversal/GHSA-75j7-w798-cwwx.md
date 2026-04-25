# Arduino Create Agent path traversal - local privilege escalation vulnerability

**GHSA**: GHSA-75j7-w798-cwwx | **CVE**: CVE-2023-43802 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-22, CWE-35

**Affected Packages**:
- **github.com/arduino/arduino-create-agent** (go): < 1.3.3

## Description

### Impact
The vulnerability affects the endpoint `/upload` which handles request with the `filename` parameter.
A user who has the ability to perform HTTP requests to the localhost interface, or is able to bypass the CORS configuration, can escalate his privileges to those of the user running the Arduino Create Agent service via a crafted HTTP POST request.
Further details are available in the references.

### Fixed Version
* `1.3.3`


### References
The issue was reported by Nozomi Networks Labs. Further details are available at the following URL:
* https://www.nozominetworks.com/blog/security-flaws-affect-a-component-of-the-arduino-create-cloud-ide

