# Code Injection in CRI-O

**GHSA**: GHSA-6x2m-w449-qwx7 | **CVE**: CVE-2022-0811 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94

**Affected Packages**:
- **github.com/cri-o/cri-o** (go): >= 1.19.0, < 1.19.6
- **github.com/cri-o/cri-o** (go): >= 1.20.0, < 1.20.7
- **github.com/cri-o/cri-o** (go): >= 1.21.0, < 1.21.6
- **github.com/cri-o/cri-o** (go): >= 1.22.0, < 1.22.3
- **github.com/cri-o/cri-o** (go): >= 1.23.0, < 1.23.2

## Description

### Impact
A flaw introduced in CRI-O version 1.19 which an attacker can use to bypass the safeguards and set arbitrary kernel parameters on the host. As a result, anyone with rights to deploy a pod on a Kubernetes cluster that uses the CRI-O runtime can abuse the `kernel.core_pattern` kernel parameter to achieve container escape and arbitrary code execution as root on any node in the cluster.

### Patches
The patches will be present in 1.19.6, 1.20.7, 1.21.6, 1.22.3, 1.23.2, 1.24.0

### Workarounds
- Users can set manage_ns_lifecycle to false, which causes the sysctls to be configured by the OCI runtime, which typically filter these cases. This option is available in 1.20 and 1.19. Newer versions don't have this option.
- An admission webhook could be created to deny pods that specify a `+` in the sysctl value of a pod.
- A [PodSecurityPolicy](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/#podsecuritypolicy) [deprecated] could be created, specifying all sysctls as forbidden like so: 
```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: sysctl-psp
spec:
  forbiddenSysctls:
    - "*"
```
However, this option will not work if any sysctls are required by any pods in the cluster.


### Credits
Credit for finding this vulnerability goes to John Walker and Manoj Ahuje of Crowdstrike. The CRI-O community deeply thanks them for the report.

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [the CRI-O repo](http://github.com/cri-o/cri-o/issues)
* To make a report, email your vulnerability to the private
[cncf-crio-security@lists.cncf.io](mailto:cncf-crio-security@lists.cncf.io) list
with the security details and the details expected for [all CRI-O bug
reports](https://github.com/cri-o/cri-o/blob/main/.github/ISSUE_TEMPLATE/bug-report.yml).

