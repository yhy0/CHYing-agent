# Grafana Missing Synchronization vulnerability

**GHSA**: GHSA-x2w4-c67p-g44j | **CVE**: CVE-2023-2801 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-662, CWE-820

**Affected Packages**:
- **github.com/grafana/grafana** (go): < 9.4.12
- **github.com/grafana/grafana** (go): >= 9.5.0, < 9.5.3

## Description

Grafana is an open-source platform for monitoring and observability. 

Using public dashboards users can query multiple distinct data sources using mixed queries. However such query has a possibility of crashing a Grafana instance.

The only feature that uses mixed queries at the moment is public dashboards, but it's also possible to cause this by calling the query API directly.

This might enable malicious users to crash Grafana instances through that endpoint.

Users may upgrade to version 9.4.12 and 9.5.3 to receive a fix.
