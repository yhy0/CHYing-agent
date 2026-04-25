# Withdrawn Advisory: Access control issues in blackbox_exporter

**GHSA**: GHSA-939c-3g97-vpvv | **CVE**: CVE-2023-26735 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-918

**Affected Packages**:
- **github.com/prometheus/blackbox_exporter** (go): <= 0.23.0

## Description

# Withdrawn Advisory
This advisory has been withdrawn because it was determined to be a configuration issue rather than a vulnerability. This link is maintained to preserve external references. For more information, see the conversation [here](https://github.com/prometheus/blackbox_exporter/issues/1024#issuecomment-1449145854).

# Original Advisory
blackbox_exporter v0.23.0 was discovered to contain an access control issue in its probe interface. This vulnerability allows attackers to detect intranet ports and services, as well as download resources.
