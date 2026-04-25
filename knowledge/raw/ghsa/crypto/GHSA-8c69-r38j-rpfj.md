# Rancher cattle-token is predictable

**GHSA**: GHSA-8c69-r38j-rpfj | **CVE**: CVE-2022-43755 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-330, CWE-331

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.6.0, < 2.6.10
- **github.com/rancher/rancher** (go): >= 2.7.0, < 2.7.1

## Description

### Impact

An issue was discovered in Rancher versions up to and including 2.6.9 and 2.7.0, where the `cattle-token` secret, used by the `cattle-cluster-agent`, is predictable. Even after the token is regenerated, it will have the same value. This issue is not present in Rancher 2.5 releases.

The `cattle-token` is used by Rancher's `cattle-cluster-agent` to connect to the Kubernetes API of Rancher provisioned downstream clusters. The problem occurs because the `cattle-token` secret does not use any random value in its composition, which causes it to always be regenerated with the same value. This can pose a serious problem if the token is compromised and needs to be recreated for security purposes.

The usage of the `cattle-token` by an unauthorized user allows to escalate privileges to the cluster owner of the affected downstream cluster. It does not allow access to Rancher's own local cluster (the cluster where Rancher is provisioned).

### Workarounds

In case it is not possible to promptly update to a patched version, a workaround is to use the [rotate script](https://github.com/rancherlabs/support-tools/tree/master/rotate-tokens) provided in the public security advisory [CVE-2021-36782 / GHSA-g7j7-h4q8-8w2f](https://github.com/rancher/rancher/security/advisories/GHSA-g7j7-h4q8-8w2f), which facilitates the rotation and creation of a new unique downstream cluster token.

### Patches

Patched versions include releases 2.6.10, 2.7.1 and later versions.

After upgrading to one of the patched versions, it is highly recommended to rotate the `cattle-token` in downstream clusters to guarantee that a new random token will be safely regenerated.

The procedure below can rotate the `cattle-token` and should be executed in each downstream cluster provisioned by Rancher. It is recommended to first test this process in an appropriate development/testing environment.

```shell
# Verify the current secret before rotating it
$ kubectl describe secrets cattle-token -n cattle-system

# Delete the secret
$ kubectl delete secrets cattle-token -n cattle-system

# Restart the cattle-cluster-agent deployment
$ kubectl rollout restart deployment/cattle-cluster-agent -n cattle-system

# Confirm that a new and different secret was generated
$ kubectl describe secrets cattle-token -n cattle-system
```

### For more information

If you have any questions or comments about this advisory:

* Reach out to [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
* Open an issue in [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
* Verify our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
