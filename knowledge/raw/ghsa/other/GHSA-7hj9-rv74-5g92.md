# Traefik HTTP header parsing could cause a denial of service 

**GHSA**: GHSA-7hj9-rv74-5g92 | **CVE**: CVE-2023-29013 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/traefik/traefik/v2** (go): < 2.9.10
- **github.com/traefik/traefik/v2** (go): = 2.10.0-rc1

## Description

### Impact

There is a vulnerability in [Go when parsing the HTTP headers](https://groups.google.com/g/golang-announce/c/Xdv6JL9ENs8/m/OV40vnafAwAJ), which impacts Traefik.
HTTP header parsing could allocate substantially more memory than required to hold the parsed headers. This behavior could be exploited to cause a denial of service.

### References

- [CVE-2023-24534](https://www.cve.org/CVERecord?id=CVE-2023-24534)

### Patches
- https://github.com/traefik/traefik/releases/tag/v2.9.10
- https://github.com/traefik/traefik/releases/tag/v2.10.0-rc2

### Workarounds

No workaround.

### For more information

If you have any questions or comments about this advisory, please [open an issue](https://github.com/traefik/traefik/issues).
