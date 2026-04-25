# Apache Airflow Providers Snowflake package allows for Special Element Injection via CopyFromExternalStageToSnowflakeOperator

**GHSA**: GHSA-9r64-3wmc-x8m8 | **CVE**: CVE-2025-50213 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-75

**Affected Packages**:
- **apache-airflow-providers-snowflake** (pip): < 6.4.0

## Description

Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) vulnerability in Apache Airflow Providers Snowflake.

This issue affects Apache Airflow Providers Snowflake: before 6.4.0.

Sanitation of table and stage parameters were added in CopyFromExternalStageToSnowflakeOperator to prevent SQL injection
Users are recommended to upgrade to version 6.4.0, which fixes the issue.
