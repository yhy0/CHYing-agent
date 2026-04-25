# Talos worker join token can be used to get elevated access level to the Talos API

**GHSA**: GHSA-7hgc-php5-77qq | **CVE**: CVE-2022-36103 | **Severity**: high (CVSS 7.2)

**CWE**: CWE-732, CWE-863

**Affected Packages**:
- **github.com/talos-systems/talos** (go): < 1.2.2

## Description

### Impact

Talos worker nodes use a join token to get accepted into the Talos cluster. A misconfigured Kubernetes environment may allow workloads to access the join token of the worker node. A malicious workload could then use the join token to construct a Talos CSR (certificate signing request). Due to improper validation while signing a worker node CSR, a Talos control plane node might issue a Talos certificate which allows full access to the Talos API to a worker node that presented a maliciously constructed CSR. Accessing the Talos API with full access on a control plane node might reveal sensitive information, which could allow full-level access to the cluster (Kubernetes and Talos PKI, etc.)

In order to exploit the weakness, a Kubernetes workload would need to access the join token, and then construct a specific kind of Talos CSR in order to obtain a privileged certificate. The Talos API join token is stored in the machine configuration on the worker node. When configured correctly, Kubernetes workloads do not have access to the machine configuration, and thus cannot access the token, nor acquire elevated privileges.

It is possible that users have misconfigured Kubernetes in such a way as to allow a workload to access the machine configuration and reveal the join token.  Misconfigurations that may allow the machine configuration to be accessed on a worker node by the Kubernetes workload are:

* allowing a `hostPath` mount to mount the machine config directly from the host filesystem (`hostPath` mounts should not be allowed for untrusted workloads, and are disabled by default in recent versions of Talos.)
* reading machine configuration from a cloud metadata server from Kubernetes pods with host networking (on cloud platforms, when machine config is stored in the cloud metadata server, and the cloud metadata server doesn't provide enough protection to prevent access from non-host workloads)

### Patches

The problem was fixed in Talos 1.2.2.

### Workarounds

Enabling the [Pod Security Standards](https://www.talos.dev/v1.2/kubernetes-guides/configuration/pod-security/)  mitigates the vulnerability by denying `hostPath` mounts and host networking by default in the [baseline](https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline) policy. Talos enables Pod Security Admission plugin by default since [Talos v1.1.0](https://www.talos.dev/v1.1/introduction/what-is-new/#pod-security-admission).

Clusters that don't run untrusted workloads are not affected.
Clusters with correct Pod Security configurations which don't allow `hostPath` mounts, and secure access to cloud metadata server (or machine configuration is not supplied via cloud metadata server) are not affected.

### References

* [Talos v1.2.2 release](https://github.com/siderolabs/talos/releases/tag/v1.2.2)
* [Fixing commit](https://github.com/siderolabs/talos/commit/9eaf33f3f274e746ca1b442c0a1a0dae0cec088f)

### For more information

If you have any questions or comments about this advisory:

* Email us at [security@siderolabs.com](mailto:security@siderolabs.com)

