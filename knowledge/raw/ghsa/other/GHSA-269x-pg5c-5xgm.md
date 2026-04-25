# Apache Airflow Execution with Unnecessary Privileges

**GHSA**: GHSA-269x-pg5c-5xgm | **CVE**: CVE-2023-39508 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-200

**Affected Packages**:
- **apache-airflow** (pip): < 2.6.0b1

## Description

Execution with Unnecessary Privileges, : Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Apache Software Foundation Apache Airflow.The "Run Task" feature enables authenticated user to bypass some of the restrictions put in place. It allows to execute code in the webserver context as well as allows to bypas limitation of access the user has to certain DAGs. The "Run Task" feature is considered dangerous and it has been removed entirely in Airflow 2.6.0.

This issue affects Apache Airflow: before 2.6.0.
