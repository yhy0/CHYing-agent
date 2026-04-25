# Apache Airflow Common SQL Provider Vulnerable to SQL Injection

**GHSA**: GHSA-5r62-mjf5-xwhj | **CVE**: CVE-2025-30473 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-89

**Affected Packages**:
- **apache-airflow-providers-common-sql** (pip): < 1.24.1

## Description

Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Apache Airflow Common SQL Provider.

When using the partition clause in SQLTableCheckOperator as parameter (which was a recommended pattern), Authenticated UI User could inject arbitrary SQL command when triggering DAG exposing partition_clause to the user.
This allowed the DAG Triggering user to escalate privileges to execute those arbitrary commands which they normally would not have.


This issue affects Apache Airflow Common SQL Provider: before 1.24.1.

Users are recommended to upgrade to version 1.24.1, which fixes the issue.
