# Kubernetes kube-apiserver unauthorized access

**GHSA**: GHSA-fp37-c92q-4pwq | **CVE**: CVE-2019-11247 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-863

**Affected Packages**:
- **k8s.io/apiextensions-apiserver** (go): >= 0.7.0, < 0.13.9
- **k8s.io/apiextensions-apiserver** (go): >= 0.14.0, < 0.14.5
- **k8s.io/apiextensions-apiserver** (go): >= 0.15.0, < 0.15.2

## Description

The Kubernetes kube-apiserver mistakenly allows access to a cluster-scoped custom resource if the request is made as if the resource were namespaced. Authorizations for the resource accessed in this manner are enforced using roles and role bindings within the namespace, meaning that a user with access only to a resource in one namespace could create, view update or delete the cluster-scoped resource (according to their namespace role privileges). Kubernetes affected versions include versions prior to 1.13.9, versions prior to 1.14.5, versions prior to 1.15.2, and versions 1.7, 1.8, 1.9, 1.10, 1.11, 1.12.
