# Rancher permissions on 'namespaces' in any API group grants 'edit' permissions on namespaces in 'core'

**GHSA**: GHSA-c85r-fwc7-45vc | **CVE**: CVE-2023-32194 | **Severity**: high (CVSS 7.2)

**CWE**: CWE-269

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.6.0, < 2.6.14
- **github.com/rancher/rancher** (go): >= 2.7.0, < 2.7.10
- **github.com/rancher/rancher** (go): >= 2.8.0, < 2.8.2

## Description

### Impact
A vulnerability has been identified when granting a `create` or `*` **global role** for a resource type of "namespaces"; no matter the API group, the subject will receive `*` permissions for core namespaces. This can lead to someone being capable of accessing, creating, updating, or deleting a namespace in the project. This includes reading or updating a namespace in the project so that it is available in other projects in which the user has the "manage-namespaces" permission or updating another namespace in which the user has normal "update" permissions to be moved into the project.

The expected behavior is to not be able to create, update, or delete a namespace in the project or move another namespace into the project since the user doesn't have any permissions on namespaces in the core API group.

Moving a namespace to another project could lead to leakage of secrets, in case the targeted project has secrets. And also can lead to the namespace being able to abuse the resource quotas of the targeted project.

### Patches
Patched versions include releases `2.6.14`, `2.7.10` and `2.8.2`.

### Workarounds
There is no direct mitigation besides updating Rancher to a patched version.

### References
If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security-related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
