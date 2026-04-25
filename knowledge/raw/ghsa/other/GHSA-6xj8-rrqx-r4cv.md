# MLflow Weak Password Requirements Authentication Bypass Vulnerability

**GHSA**: GHSA-6xj8-rrqx-r4cv | **CVE**: CVE-2025-11200 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-521

**Affected Packages**:
- **mlflow** (pip): < 2.22.0rc0

## Description

MLflow Weak Password Requirements Authentication Bypass Vulnerability. This vulnerability allows remote attackers to bypass authentication on affected installations of MLflow. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the handling of passwords. The issue results from weak password requirements. An attacker can leverage this vulnerability to bypass authentication on the system. Was ZDI-CAN-26916.
