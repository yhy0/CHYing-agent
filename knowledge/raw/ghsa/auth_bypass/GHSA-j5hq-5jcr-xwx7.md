#  github.com/rancher/steve's users can issue watch commands for arbitrary resources

**GHSA**: GHSA-j5hq-5jcr-xwx7 | **CVE**: CVE-2024-52280 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-200, CWE-287

**Affected Packages**:
- **github.com/rancher/steve** (go): < 0.0.0-20241029132712-2175e090fe4b

## Description

### Impact
A vulnerability has been discovered in Steve API (Kubernetes API Translator) in which users can watch resources they are not allowed to access, when they have at least some generic permissions on the type. For example, a user who can get a single secret in a single namespace can get all secrets in every namespace.

During a `watch` request for a single ID, the following occurs:
- In the case of a watch request for a single resource, Steve API will return a partition with the requested resource in it. In other cases, it will check the user's access when constructing partitions.
- When a watch request for a single resource is issued, instead of using a client which impersonates the user making the request, Steve API will use the admin client, which can read all resources.

This allows any requester to see the contents of any object such as secret keys, signing certificates, API tokens.

Please consult the associated  [MITRE ATT&CK - Technique - Valid Accounts](https://attack.mitre.org/techniques/T1078/003/) and  [MITRE ATT&CK - Technique - Container and Resource Discovery](https://attack.mitre.org/techniques/T1613/) for further information about this category of attack.

### Patches
To address this issue, the fix introduces a change in the behavior of the Steve API.

When issuing a `watch` request with an ID specified, the requester's permissions are now correctly honoured. This will deny events for objects the requester cannot actually access. Previously these events were returned unconditionally, allowing any requester to see the contents of any object.

Patched versions include the following commits:

| Branch    | Commit |
| -------- | ------- |
| main | https://github.com/rancher/steve/commit/2175e090fe4b1e603a54e1cdc5148a2b1c11b4d9 |
| release/v2.9 | https://github.com/rancher/steve/commit/6e30359c652333a49e229b2791c9b403d5ef81a9 |
| release/v2.8 | https://github.com/rancher/steve/commit/c744f0b17b88ff5e2fcabc60841174d878ddc88e |

### Workarounds
There are no workarounds for this issue. Users are recommended to upgrade, as soon as possible, to a version of Steve API/Rancher Manager which contains the fixes.

### References
If you have any questions or comments about this advisory:
- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security-related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
