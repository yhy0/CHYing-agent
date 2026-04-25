# Authenticated user can gain unauthorized shell pod and kubectl access in the local cluster

**GHSA**: GHSA-g25r-gvq3-wrq7 | **CVE**: CVE-2022-21953 | **Severity**: high (CVSS 7.4)

**CWE**: CWE-284, CWE-285, CWE-862

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.5.0, < 2.5.17
- **github.com/rancher/rancher** (go): >= 2.6.0, < 2.6.10
- **github.com/rancher/rancher** (go): >= 2.7.0, < 2.7.1

## Description

### Impact

An issue was discovered in Rancher where an authorization logic flaw allows an authenticated user on any downstream cluster to (1) open a shell pod in the Rancher `local` cluster and (2) have limited `kubectl` access to it. The expected behavior is that a user does not have such access in the Rancher `local` cluster unless explicitly granted.

This issue does not allow the user to escalate privileges in the `local` cluster directly (this would require another vulnerability to be exploited).

The security issue happens in two different ways:

1. Shell pod access - This is when a user opens a shell pod in the Rancher UI to a downstream cluster that the user has permission to access. The web request can be intercepted using the browser's web inspector/network console or a proxy tool to change the shell's destination to the Rancher `local` cluster instead of the desired downstream cluster.

   - This flaw cannot be exploited to access a downstream cluster that the user has no permissions to.

   - The shell pod runs with a limited non-root user, reducing the severity of this issue. However, even as a non-root user, it is still possible download and run binaries inside the shell pod.

   - The blast radius of this issue can increase based on the configuration of the `local` cluster. For example:

      - If the `local` cluster has unlimited network access, e.g. to the Internet, the user can open a reverse network connection to the shell pod.

      - Or access the cloud metadata API of the underlying cloud infrastructure, where the user can extract the credentials associated with the `local` cluster and use them to interact with the cloud environment (this will be limited by the permissions granted to the cloud credentials in question). 

      - Check further recommendations about liming access to the cloud metadata API in Rancher's [security best practices](https://ranchermanager.docs.rancher.com/reference-guides/rancher-security/kubernetes-security-best-practices).

2. Kubectl access - When downloading the kubeconfig file of a downstream cluster that the user has access to, the `server` cluster address in the kubeconfig file can be changed to point to the Rancher `local` cluster instead of the intended downstream cluster.

     - This can also be achieved by crafting a kubeconfig using a Rancher token instead of using the kubeconfig from an active cluster. 

    - This flaw cannot be exploited to access a downstream cluster that the user has no permissions to.

Notes:
- Rancher `local` cluster means the cluster where Rancher is installed. It is named as `local` inside the list of clusters in the Rancher UI.
- Audit logs in Rancher can be used to identify possible abuses of this issue, by tracking API requests to the user ID of the user that performed the action. API audit logs can be enabled as described in the [documentation](https://ranchermanager.docs.rancher.com/how-to-guides/advanced-user-guides/enable-api-audit-log) when set to level `1` or above.

### Workarounds

There is no workaround or direct mitigation besides updating to a patched Rancher version.

### Patches

Patched versions include releases 2.5.17, 2.6.10, 2.7.1 and later versions.

### For more information

If you have any questions or comments about this advisory:

* Reach out to [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
* Open an issue in [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
* Verify our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
