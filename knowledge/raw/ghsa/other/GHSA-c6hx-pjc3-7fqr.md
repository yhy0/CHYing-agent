# Traefik HTTP/2 connections management could cause a denial of service

**GHSA**: GHSA-c6hx-pjc3-7fqr | **CVE**: CVE-2022-39271 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400, CWE-755

**Affected Packages**:
- **github.com/traefik/traefik/v2** (go): < 2.8.8
- **github.com/traefik/traefik/v2** (go): >= 2.9.0-rc1, < 2.9.0-rc5

## Description

### Impact

There is a potential vulnerability in Traefik managing HTTP/2 connections.
A closing HTTP/2 server connection could hang forever because of a subsequent fatal error. This failure mode could be exploited to cause a denial of service.

### Patches

Traefik v2.8.x: https://github.com/traefik/traefik/releases/tag/v2.8.8
Traefik v2.9.x: https://github.com/traefik/traefik/releases/tag/v2.9.0-rc5

### Workarounds

No workaround.

### For more information

If you have any questions or comments about this advisory, please [open an issue](https://github.com/traefik/traefik/issues).

