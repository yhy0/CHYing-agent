# Apache Airflow JDBC Provider Improper Input Validation vulnerability

**GHSA**: GHSA-mm87-c3x2-6f89 | **CVE**: CVE-2023-22886 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20

**Affected Packages**:
- **apache-airflow-providers-jdbc** (pip): < 4.0.0

## Description

Improper Input Validation vulnerability in Apache Software Foundation Apache Airflow JDBC Provider. Airflow JDBC Provider Connection’s [Connection URL] parameters had no restrictions, which made it possible to implement RCE attacks via different type JDBC drivers, obtain airflow server permission. This issue affects Apache Airflow JDBC Provider: before 4.0.0.



