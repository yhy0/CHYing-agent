# Apache Airflow vulnerable to Code Injection in the web-server context via LogTemplate table

**GHSA**: GHSA-r837-hpv7-pc2f | **CVE**: CVE-2024-56373 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-94

**Affected Packages**:
- **apache-airflow** (pip): < 2.11.1

## Description

DAG Author (who already has quite a lot of permissions) could manipulate database of Airflow 2 in the way to execute arbitrary code in the web-server context, which they should normally not be able to do, leading to potentially remote code execution in the context of web-server (server-side) as a result of a user viewing historical task information.

The functionality responsible for that (log template history) has been disabled by default in 2.11.1 and users should upgrade to Airflow 3 if they want to continue to use log template history. They can also manually modify historical log file names if they want to see historical logs that were generated before the last log template change.
