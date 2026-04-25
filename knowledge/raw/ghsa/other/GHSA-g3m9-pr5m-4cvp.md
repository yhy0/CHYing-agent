# Airflow Sqoop Provider RCE Vulnerability

**GHSA**: GHSA-g3m9-pr5m-4cvp | **CVE**: CVE-2023-27604 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20

**Affected Packages**:
- **apache-airflow-providers-apache-sqoop** (pip): < 4.0.0

## Description

Apache Airflow Sqoop Provider, versions before 4.0.0, is affected by a vulnerability that allows an attacker pass parameters with the connections, which makes it possible to implement RCE attacks via ‘sqoop import --connect’, obtain airflow server permissions, etc. The attacker needs to be logged in and have authorization (permissions) to create/edit connections.

 It is recommended to upgrade to a version that is not affected.
This issue was reported independently by happyhacking-k, And Xie Jianming and LiuHui of Caiji Sec Team also reported it.
