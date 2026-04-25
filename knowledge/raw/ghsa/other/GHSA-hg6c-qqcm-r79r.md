# Apache Airflow Hive Provider Beeline remote code execution with Principal

**GHSA**: GHSA-hg6c-qqcm-r79r | **CVE**: CVE-2023-35797 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-20

**Affected Packages**:
- **apache-airflow-providers-apache-hive** (pip): < 6.1.1

## Description

Improper Input Validation vulnerability in Apache Software Foundation Apache Airflow Hive Provider.
This issue affects Apache Airflow Apache Hive Provider: before 6.1.1.

Before version 6.1.1 it was possible to bypass the security check to RCE via
principal parameter. For this to be exploited it requires access to modifying the connection details.

It is recommended updating provider version to 6.1.1 in order to avoid this vulnerability.
