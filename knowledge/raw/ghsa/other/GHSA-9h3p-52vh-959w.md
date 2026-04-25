# ingress-nginx's `nginx.ingress.kubernetes.io/auth-method` Ingress annotation can be used to inject configuration into nginx

**GHSA**: GHSA-9h3p-52vh-959w | **CVE**: CVE-2026-1580 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20

**Affected Packages**:
- **k8s.io/ingress-nginx** (go): < 1.13.7
- **k8s.io/ingress-nginx** (go): >= 1.14.0, < 1.14.3

## Description

A security issue was discovered in ingress-nginx where the `nginx.ingress.kubernetes.io/auth-method` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)
