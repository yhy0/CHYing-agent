# BentoML deserialization vulnerability

**GHSA**: GHSA-9g44-gwvm-hc44 | **CVE**: CVE-2024-9070 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **bentoml** (pip): <= 1.4.5

## Description

A deserialization vulnerability exists in BentoML's runner server in bentoml/bentoml versions <=1.3.4.post1. By setting specific parameters, an attacker can execute unauthorized arbitrary code on the server, causing severe harm. The vulnerability is triggered when the args-number parameter is greater than 1, leading to automatic deserialization and arbitrary code execution.
