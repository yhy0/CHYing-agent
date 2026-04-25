# Traefik vulnerable to denial of service with Content-length header

**GHSA**: GHSA-4vwx-54mw-vqfw | **CVE**: CVE-2024-28869 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-404, CWE-755

**Affected Packages**:
- **github.com/traefik/traefik/v3** (go): >= 3.0.0-beta3, <= 3.0.0-rc4
- **github.com/traefik/traefik/v2** (go): <= 2.11.1
- **github.com/traefik/traefik** (go): <= 2.11.1

## Description

There is a potential vulnerability in Traefik managing requests with `Content-length` and no `body` .

Sending a `GET` request to any Traefik endpoint with the `Content-length` request header results in an indefinite hang with the default configuration. This vulnerability can be exploited by attackers to induce a denial of service.

## Patches

- https://github.com/traefik/traefik/releases/tag/v2.11.2
- https://github.com/traefik/traefik/releases/tag/v3.0.0-rc5

## Workarounds

For affected versions, this vulnerability can be mitigated by configuring the [readTimeout](https://doc.traefik.io/traefik/routing/entrypoints/#respondingtimeouts) option.

## For more information

If you have any questions or comments about this advisory, please [open an issue](https://github.com/traefik/traefik/issues).
