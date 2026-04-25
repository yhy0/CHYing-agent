# postgraas-server vulnerable to SQL injection

**GHSA**: GHSA-vghm-8cjp-hjw6 | **CVE**: CVE-2018-25088 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **postgraas-server** (pip): < 2.0.0

## Description

A vulnerability, which was classified as critical, was found in Blue Yonder postgraas_server up to 2.0.0b2. Affected is the function `_create_pg_connection/create_postgres_db` of the file `postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py` of the component PostgreSQL Backend Handler. The manipulation leads to sql injection. Upgrading to version 2.0.0 is able to address this issue. The patch is identified as 7cd8d016edc74a78af0d81c948bfafbcc93c937c. It is recommended to upgrade the affected component. VDB-234246 is the identifier assigned to this vulnerability.
