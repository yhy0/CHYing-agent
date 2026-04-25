# ingress-nginx controller - configuration injection via unsanitized auth-url annotation

**GHSA**: GHSA-fwwp-xcxw-39vq | **CVE**: CVE-2025-24514 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-15, CWE-20

**Affected Packages**:
- **k8s.io/ingress-nginx** (go): < 1.11.5
- **k8s.io/ingress-nginx** (go): >= 1.12.0-beta.0, < 1.12.1

## Description

A security issue was discovered in [ingress-nginx](https://github.com/kubernetes/ingress-nginx) where the `auth-url` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)
