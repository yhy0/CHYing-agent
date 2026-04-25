# KubePi Privilege Escalation vulnerability

**GHSA**: GHSA-757p-vx43-fp9r | **CVE**: CVE-2023-37917 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-269

**Affected Packages**:
- **github.com/KubeOperator/kubepi** (go): < 1.6.5

## Description

### Summary
A normal user has permission to create/update users, they can become admin by editing the `isadmin` value in the request


### PoC
Change the value of the `isadmin` field in the request to true:
https://drive.google.com/file/d/1e8XJbIFIDXaFiL-dqn0a0b6u7o3CwqSG/preview

### Impact
Elevate user privileges

