# Apache superset missing check for default SECRET_KEY

**GHSA**: GHSA-5cx2-vq3h-x52c | **CVE**: CVE-2023-27524 | **Severity**: high (CVSS 8.9)

**CWE**: CWE-1188

**Affected Packages**:
- **apache-superset** (pip): < 2.1.0

## Description

Session Validation attacks in Apache Superset versions up to and including 2.0.1. Installations that have not altered the default configured SECRET_KEY according to installation instructions allow for an attacker to authenticate and access unauthorized resources. This does not affect Superset administrators who have changed the default value for SECRET_KEY config.
