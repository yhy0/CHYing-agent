# ingress-nginx's `rules.http.paths.path` Ingress field can be used to inject configuration into nginx

**GHSA**: GHSA-jx8c-56mg-h6vp | **CVE**: CVE-2026-24512 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20

**Affected Packages**:
- **k8s.io/ingress-nginx** (go): < 1.13.7
- **k8s.io/ingress-nginx** (go): >= 1.14.0, < 1.14.3

## Description

A security issue was discovered in ingress-nginx. Tthe `rules.http.paths.path` Ingress field can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)
