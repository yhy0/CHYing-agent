# Grafana Cross-Site-Scripting (XSS) via custom loaded frontend plugin

**GHSA**: GHSA-q53q-gxq9-mgrj | **CVE**: CVE-2025-4123 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/grafana/grafana** (go): < 0.0.0-20250521183405-c7a690348df7

## Description

A cross-site scripting (XSS) vulnerability exists in Grafana caused by combining a client path traversal and open redirect. This allows attackers to redirect users to a website that hosts a frontend plugin that will execute arbitrary JavaScript. This vulnerability does not require editor permissions and if anonymous access is enabled, the XSS will work. If the Grafana Image Renderer plugin is installed, it is possible to exploit the open redirect to achieve a full read SSRF.

The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.
