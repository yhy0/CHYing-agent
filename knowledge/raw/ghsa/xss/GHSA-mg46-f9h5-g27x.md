# Apache Sling Engine vulnerable to cross-site scripting (XSS) that can lead to privilege escalation

**GHSA**: GHSA-mg46-f9h5-g27x | **CVE**: CVE-2022-45064 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-79

**Affected Packages**:
- **org.apache.sling:org.apache.sling.engine** (maven): < 2.14.0

## Description

The SlingRequestDispatcher doesn't correctly implement the RequestDispatcher API resulting in a generic type of include-based cross-site scripting issues on the Apache Sling level. The vulnerability is exploitable by an attacker that is able to include a resource with specific content-type and control the include path (i.e. writing content). The impact of a successful attack is privilege escalation to administrative power.

Please update to Apache Sling Engine version 2.14.0 or newer and enable the "Check Content-Type overrides" configuration option.





