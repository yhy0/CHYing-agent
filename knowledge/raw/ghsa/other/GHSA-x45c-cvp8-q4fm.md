# Capsule vulnerable to privilege escalation by ServiceAccount deployed in a Tenant Namespace

**GHSA**: GHSA-x45c-cvp8-q4fm | **CVE**: CVE-2022-46167 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/clastix/capsule** (go): <= 0.1.2

## Description

Capsule implements a multi-tenant and policy-based environment in a Kubernetes cluster. A ServiceAccount deployed in a Tenant Namespace, when granted with `PATCH` capabilities on its own Namespace, is able to edit it and remove the Owner Reference, breaking the reconciliation of the Capsule Operator and removing all the enforcement like Pod Security annotations, Network Policies, Limit Range and Resource Quota items.

With that said, an attacker could detach the Namespace from a Tenant that is forbidding starting privileged Pods using the Pod Security labels by removing the OwnerReference, removing the enforcement labels, and being able to start privileged containers that would be able to start a generic Kubernetes privilege escalation.

### Patches

Patches have been released for version 0.1.3 and all users must upgrade to this release.

### Workarounds

N.A.

### References

N.A.

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [github.com/clastix/capsule](https://github.com/clastix/capsule)
* Reach out on [#capsule](https://kubernetes.slack.com/archives/C03GETTJQRL) channel available on Kubernetes Slack workspace

