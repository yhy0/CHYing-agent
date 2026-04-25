# H2O affected by a deserialization vulnerability

**GHSA**: GHSA-5w3j-gwgh-4rfv | **CVE**: CVE-2025-6544 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **ai.h2o:h2o-core** (maven): <= 3.46.0.7
- **h2o** (pip): <= 3.46.0.7

## Description

A deserialization vulnerability exists in h2oai/h2o-3 versions <= 3.46.0.7, allowing attackers to read arbitrary system files and execute arbitrary code. The vulnerability arises from improper handling of JDBC connection parameters, which can be exploited by bypassing regular expression checks and using double URL encoding. This issue impacts all users of the affected versions.
