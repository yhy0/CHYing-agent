# Grafana is vulnerable to XSS attacks through open redirects and path traversal

**GHSA**: GHSA-vqph-p5vc-g644 | **CVE**: CVE-2025-6023 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/grafana/grafana** (go): < 1.9.2-0.20250521205822-0ba0b99665a9

## Description

An open redirect vulnerability has been identified in Grafana OSS that can be exploited to achieve XSS attacks. The vulnerability was introduced in Grafana v11.5.0.

The open redirect can be chained with path traversal vulnerabilities to achieve XSS.

Fixed in versions 12.0.2+security-01, 11.6.3+security-01, 11.5.6+security-01, 11.4.6+security-01 and 11.3.8+security-01
