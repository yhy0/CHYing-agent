# Apache Airflow vulnerable arbitrary code execution via Spark server

**GHSA**: GHSA-8q28-pw9g-w82c | **CVE**: CVE-2023-40195 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **apache-airflow-providers-apache-spark** (pip): < 4.1.3

## Description

Deserialization of Untrusted Data, Inclusion of Functionality from Untrusted Control Sphere vulnerability in Apache Software Foundation Apache Airflow Spark Provider.

When the Apache Spark provider is installed on an Airflow deployment, an Airflow user that is authorized to configure Spark hooks can effectively run arbitrary code on the Airflow node by pointing it at a malicious Spark server. Prior to version 4.1.3, this was not called out in the documentation explicitly, so it is possible that administrators provided authorizations to configure Spark hooks without taking this into account. We recommend administrators to review their configurations to make sure the authorization to configure Spark hooks is only provided to fully trusted users.

To view the warning in the docs please visit  https://airflow.apache.org/docs/apache-airflow-providers-apache-spark/4.1.3/connections/spark.html 


