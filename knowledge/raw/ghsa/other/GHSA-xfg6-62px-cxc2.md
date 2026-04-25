# Duplicate Advisory: SQL injection in pgjdbc

**GHSA**: GHSA-xfg6-62px-cxc2 | **CVE**: N/A | **Severity**: critical (CVSS 10.0)

**CWE**: N/A

**Affected Packages**:
- **org.postgresql:postgresql** (maven): >= 42.7.0, < 42.7.2
- **org.postgresql:postgresql** (maven): >= 42.6.0, < 42.6.1
- **org.postgresql:postgresql** (maven): >= 42.5.0, < 42.5.5
- **org.postgresql:postgresql** (maven): >= 42.4.0, < 42.4.4
- **org.postgresql:postgresql** (maven): >= 42.3.0, < 42.3.9
- **org.postgresql:postgresql** (maven): < 42.2.8

## Description

## Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-24rp-q3w6-vc56. This link is maintained to preserve external references.

## Original Description
pgjdbc, the PostgreSQL JDBC Driver, allows attacker to inject SQL if using PreferQueryMode=SIMPLE. Note this is not the default. In the default mode there is no vulnerability. A placeholder for a numeric value must be immediately preceded by a minus. There must be a second placeholder for a string value after the first placeholder; both must be on the same line. By constructing a matching string payload, the attacker can inject SQL to alter the query,bypassing the protections that parameterized queries bring against SQL Injection attacks. Versions before 42.7.2, 42.6.1, 42.5.5, 42.4.4, 42.3.9, and 42.2.8 are affected.
