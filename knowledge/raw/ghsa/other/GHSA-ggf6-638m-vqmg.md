# Netmaker vulnerable to Insufficient Granularity of Access Control

**GHSA**: GHSA-ggf6-638m-vqmg | **CVE**: CVE-2022-36110 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-285, CWE-1220

**Affected Packages**:
- **github.com/gravitl/netmaker** (go): < 0.15.1

## Description

### Impact
Improper Authorization functions leads to non-privileged users running privileged API calls. If you have added users to your Netmaker platform who whould not have admin privileges, they could use their auth token to run admin-level functions via the API.

In addition, differing response codes based on function calls allowed non-users to potentially brute force the determination of names of networks on the system.

### Patches
This problem has been patched in v0.15.1. To apply:

1. docker-compose down
2. docker pull gravitl/netmaker:v0.15.1
3. docker-compose up -d

### For more information
If you have any questions or comments about this advisory:

Email us at [info@netmaker.io](mailto:info@netmaker.io)
This vulnerability was brought to our attention by @tweidinger
