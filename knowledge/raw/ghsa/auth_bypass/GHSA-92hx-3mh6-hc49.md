# kube-apiserver authentication bypass vulnerability

**GHSA**: GHSA-92hx-3mh6-hc49 | **CVE**: CVE-2023-1260 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-288

**Affected Packages**:
- **github.com/openshift/apiserver-library-go** (go): < 0.0.0-20230621

## Description

An authentication bypass vulnerability was discovered in kube-apiserver. This issue could allow a remote, authenticated attacker who has been given permissions "update, patch" the "pods/ephemeralcontainers" subresource beyond what the default is. They would then need to create a new pod or patch one that they already have access to. This might allow evasion of SCC admission restrictions, thereby gaining control of a privileged pod.
