# Rancher Recreates Default User With Known Password Despite Deletion

**GHSA**: GHSA-xh8x-j8h3-m5ph | **CVE**: CVE-2019-11202 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.0.0, <= 2.0.13
- **github.com/rancher/rancher** (go): >= 2.1.0, <= 2.1.8
- **github.com/rancher/rancher** (go): >= 2.2.0, < 2.2.2

## Description

An issue was discovered that affects the following versions of Rancher: v2.0.0 through v2.0.13, v2.1.0 through v2.1.8, and v2.2.0 through 2.2.1. When Rancher starts for the first time, it creates a default admin user with a well-known password. After initial setup, the Rancher administrator may choose to delete this default admin user. If Rancher is restarted, the default admin user will be recreated with the well-known default password. An attacker could exploit this by logging in with the default admin credentials. This can be mitigated by deactivating the default admin user rather than completing deleting them.
