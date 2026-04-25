# Nginx-UI vulnerable to authenticated RCE through injecting into the application config via CRLF

**GHSA**: GHSA-qcjq-7f7v-pvc8 | **CVE**: CVE-2024-23828 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-74

**Affected Packages**:
- **github.com/0xJacky/Nginx-UI** (go): < 2.0.0-beta.12

## Description

### Summary

Fix bypass to the following bugs

- https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-pxmr-q2x3-9x9m
- https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-8r25-68wm-jw35

Allowing to inject directly in the `app.ini` via CRLF to change the value of `test_config_cmd` and `start_cmd` resulting in an Authenticated RCE

### Impact
Authenticated Remote execution on the host
