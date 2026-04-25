# NVIDIA Container Toolkit for all platforms contains an Untrusted Search Path

**GHSA**: GHSA-vmg3-7v43-9g23 | **CVE**: CVE-2025-23266 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-426

**Affected Packages**:
- **github.com/NVIDIA/nvidia-container-toolkit** (go): < 1.17.8
- **github.com/NVIDIA/k8s-device-plugin** (go): < 0.17.3
- **github.com/NVIDIA/gpu-operator** (go): < 25.3.2
- **github.com/NVIDIA/mig-parted** (go): < 0.12.2

## Description

NVIDIA Container Toolkit for all platforms contains a vulnerability in some hooks used to initialize the container, where an attacker could execute arbitrary code with elevated permissions. A successful exploit of this vulnerability might lead to escalation of privileges, data tampering, information disclosure, and denial of service.
