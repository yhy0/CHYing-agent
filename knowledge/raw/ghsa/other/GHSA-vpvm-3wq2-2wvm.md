# Opencontainers runc Incorrect Authorization vulnerability

**GHSA**: GHSA-vpvm-3wq2-2wvm | **CVE**: CVE-2023-27561 | **Severity**: high (CVSS 7.0)

**CWE**: CWE-706

**Affected Packages**:
- **github.com/opencontainers/runc** (go): >= 1.0.0-rc95, < 1.1.5

## Description

runc 1.0.0-rc95 through 1.1.4 has Incorrect Access Control leading to Escalation of Privileges, related to `libcontainer/rootfs_linux.go`. To exploit this, an attacker must be able to spawn two containers with custom volume-mount configurations, and be able to run custom images. NOTE: this issue exists because of a CVE-2019-19921 regression.
