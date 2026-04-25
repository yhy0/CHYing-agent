# ingress-nginx admission controller RCE escalation

**GHSA**: GHSA-mgvx-rpfc-9mpv | **CVE**: CVE-2025-1974 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-653

**Affected Packages**:
- **k8s.io/ingress-nginx** (go): < 1.11.5
- **k8s.io/ingress-nginx** (go): >= 1.12.0-beta.0, < 1.12.1

## Description

A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)
