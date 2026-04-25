# Rancher users retain access after moving namespaces into projects they don't have access to

**GHSA**: GHSA-8vhc-hwhc-cpj4 | **CVE**: CVE-2020-10676 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.6.0, < 2.6.13
- **github.com/rancher/rancher** (go): >= 2.7.0, < 2.7.4

## Description

### Impact
A vulnerability was identified in which users with update privileges on a namespace, can move that namespace into a project they don't have access to. After the namespace transfer is completed, their previous permissions are still preserved, which enables them to gain access to project-specific resources (such as [project secrets](https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/kubernetes-resources-setup/secrets#creating-secrets-in-projects)). In addition, resources in the namespace will now count toward the [quota limit](https://ranchermanager.docs.rancher.com/how-to-guides/advanced-user-guides/manage-projects/manage-project-resource-quotas/about-project-resource-quotas) of the new project, potentially causing availability issues.

User with roles `Project Owner` and `Project Member` on the source project can exploit this vulnerability; however, this would also apply to custom roles with similar privileges. 

The patched version include an improved RBAC mechanism, which checks if the user has the correct permissions before the namespace move takes place.

### Patches
Patched versions include releases `2.6.13`, `2.7.4` and later versions.

### Workarounds
There is no direct mitigation besides updating Rancher to a patched version.

### For more information
If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
