# Cross Site Scripting in OpenTSDB

**GHSA**: GHSA-9chv-3w6c-jq9w | **CVE**: CVE-2023-25827 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-79

**Affected Packages**:
- **net.opentsdb:opentsdb** (maven): <= 2.4.1

## Description

Due to insufficient validation of parameters reflected in error messages by the legacy HTTP query API and the logging endpoint, it is possible to inject and execute malicious JavaScript within the browser of a targeted OpenTSDB user. This issue shares the same root cause as CVE-2018-13003, a reflected XSS vulnerability with the suggestion endpoint.


