# Apache Airflow has DAG Author Code Execution possibility in airflow-scheduler

**GHSA**: GHSA-g5hv-r743-v8pm | **CVE**: CVE-2024-39877 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-94, CWE-277

**Affected Packages**:
- **apache-airflow** (pip): >= 2.4.0, < 2.9.3

## Description

Apache Airflow 2.4.0, and versions before 2.9.3, has a vulnerability that allows authenticated DAG authors to craft a doc_md parameter in a way that could execute arbitrary code in the scheduler context, which should be forbidden according to the Airflow Security model. Users should upgrade to version 2.9.3 or later which has removed the vulnerability.
