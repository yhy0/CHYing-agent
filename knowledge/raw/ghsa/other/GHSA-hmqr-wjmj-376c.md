# Netmaker has Insufficient Authorization in Host Token Verification

**GHSA**: GHSA-hmqr-wjmj-376c | **CVE**: CVE-2026-29194 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/gravitl/netmaker** (go): < 1.5.0

## Description

The Authorise middleware in Netmaker incorrectly validates host JWT tokens. When a route permits host authentication (hostAllowed=true), a valid host token bypasses all subsequent authorisation checks without verifying that the host is authorised to access the specific requested resource. Any entity possessing knowledge of object identifiers (node IDs, host IDs) can craft a request with an arbitrary valid host token to access, modify, or delete resources belonging to other hosts. Affected endpoints include node info retrieval, host deletion, MQTT signal transmission, fallback host updates, and failover operations.


> Credits
> Artem Danilov (Positive Technologies)
