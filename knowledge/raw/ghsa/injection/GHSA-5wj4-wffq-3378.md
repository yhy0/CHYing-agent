# Ingress nginx annotation injection causes arbitrary command execution

**GHSA**: GHSA-5wj4-wffq-3378 | **CVE**: CVE-2023-5043 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-20, CWE-74

**Affected Packages**:
- **k8s.io/ingress-nginx** (go): < 1.9.0

## Description

### Issue Details
A security issue was identified in ingress-nginx where the nginx.ingress.kubernetes.io/configuration-snippet annotation on an Ingress object (in the networking.k8s.io or extensions API group) can be used to inject arbitrary commands, and obtain the credentials of the ingress-nginx controller. In the default configuration, that credential has access to all secrets in the cluster.

This issue has been rated High (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L), and assigned CVE-2023-5043.

### Affected Components and Configurations
This bug affects ingress-nginx. If you do not have ingress-nginx installed on your cluster, you are not affected. You can check this by running kubectl get po -n ingress-nginx.

If you are running the “chrooted” ingress-nginx controller introduced in v1.2.0 (gcr.io/k8s-staging-ingress-nginx/controller-chroot), command execution is possible but credential extraction is not, so the High severity does not apply.

Multi-tenant environments where non-admin users have permissions to create Ingress objects are most affected by this issue.

#### Affected Versions
<v1.9.0
#### Versions allowing mitigation
v1.9.0
### Mitigation
Ingress Administrators should set the --enable-annotation-validation flag to enforce restrictions on the contents of ingress-nginx annotation fields.

### Detection
If you find evidence that this vulnerability has been exploited, please contact security@kubernetes.io

### Additional Details
See ingress-nginx Issue [#10571](https://github.com/kubernetes/ingress-nginx/issues/10571) for more details.

### Acknowledgements
This vulnerability was reported by suanve

Thank You,
CJ Cullen on behalf of the Kubernetes Security Response Committee
