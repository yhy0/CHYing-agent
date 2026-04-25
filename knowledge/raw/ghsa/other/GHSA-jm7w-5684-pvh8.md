# FASTJSON Includes Functionality from Untrusted Control Sphere 

**GHSA**: GHSA-jm7w-5684-pvh8 | **CVE**: CVE-2025-70974 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-829

**Affected Packages**:
- **com.alibaba:fastjson** (maven): < 1.2.48

## Description

Fastjson before 1.2.48 mishandles autoType because, when an `@type` key is in a JSON document, and the value of that key is the name of a Java class, there may be calls to certain public methods of that class. Depending on the behavior of those methods, there may be JNDI injection with an attacker-supplied payload located elsewhere in that JSON document. This was exploited in the wild in 2023 through 2025. NOTE: this issue exists because of an incomplete fix for CVE-2017-18349. Also, a later bypass is covered by CVE-2022-25845.
