# Cross-site scripting on application summary component

**GHSA**: GHSA-jwv5-8mqv-g387 | **CVE**: CVE-2024-28175 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/argoproj/argo-cd/v2** (go): >= 2.9.0, < 2.9.8
- **github.com/argoproj/argo-cd/v2** (go): >= 2.10.0, < 2.10.3
- **github.com/argoproj/argo-cd/v2** (go): >= 2.0.0, < 2.8.12
- **github.com/argoproj/argo-cd** (go): >= 1.0.0, <= 1.8.7

## Description

### Summary

Due to the improper URL protocols filtering of links specified in the `link.argocd.argoproj.io` annotations in the application summary component, an attacker can achieve cross-site scripting with elevated permissions.

### Impact

All unpatched versions of Argo CD starting with v1.0.0 are vulnerable to a cross-site scripting (XSS) bug allowing a malicious user to inject a javascript: link in the UI. When clicked by a victim user, the script will execute with the victim's permissions (up to and including admin).

This vulnerability allows an attacker to perform arbitrary actions on behalf of the victim via the API, such as creating, modifying, and deleting Kubernetes resources.

### Patches
A patch for this vulnerability has been released in the following Argo CD versions:

* v2.10.3
* v2.9.8
* v2.8.12

### Workarounds

There are no completely-safe workarounds besides **upgrading**. The safest alternative, if upgrading is not possible, would be to create a [Kubernetes admission controller](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/) to reject any resources with an annotation starting with `link.argocd.argoproj.io` or reject the resource if the value use an improper URL protocol. This validation will need to be applied in all clusters managed by ArgoCD.

#### Mitigations

1. Avoid clicking external links presented in the UI.
The link's title is user-configurable. So even if you hover the link, and the tooltip looks safe, the link might be malicious. The only way to be certain that the link is safe is to inspect the page's source.
2. Carefully limit who has permissions to edit Kubernetes resource manifests (this is configured in [RBAC](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/) for ArgoCD). 
The external-links are set as annotations on Kubernetes resources. Any persona with write access to resources managed by ArgoCD could be an actor.

### References
[Documentation for the external links feature](https://argo-cd.readthedocs.io/en/stable/user-guide/external-url/)

### Credits

Disclosed by [RyotaK](https://ryotak.net) (@Ry0taK)

### For more information

- Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc) or [discussions](https://github.com/argoproj/argo-cd/discussions)
- Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd
