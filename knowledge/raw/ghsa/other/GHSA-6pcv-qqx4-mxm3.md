# Minikube RCE via DNS Rebinding

**GHSA**: GHSA-6pcv-qqx4-mxm3 | **CVE**: CVE-2018-1002103 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-352

**Affected Packages**:
- **k8s.io/minikube** (go): >= 0.3.0, <= 0.29.0

## Description

In Minikube versions 0.3.0-0.29.0, minikube exposes the Kubernetes Dashboard listening on the VM IP at port 30000. In VM environments where the IP is easy to predict, the attacker can use DNS rebinding to indirectly make requests to the Kubernetes Dashboard, create a new Kubernetes Deployment running arbitrary code. If minikube mount is in use, the attacker could also directly access the host filesystem.
