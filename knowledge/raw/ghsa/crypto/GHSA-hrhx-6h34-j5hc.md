# Skip the router TLS configuration when the host header is an FQDN

**GHSA**: GHSA-hrhx-6h34-j5hc | **CVE**: CVE-2022-23632 | **Severity**: high (CVSS 7.4)

**CWE**: CWE-295

**Affected Packages**:
- **github.com/traefik/traefik/v2** (go): < 2.6.1

## Description

### Impact

People that configure mTLS between Traefik and clients.

For a request, the TLS configuration choice can be different than the router choice, which implies the use of a wrong TLS configuration.

- When sending a request using FQDN handled by a router configured with a dedicated TLS configuration, the TLS configuration falls back to the default configuration that might not correspond to the configured one.

- If the CNAME flattening is enabled, the selected TLS configuration is the SNI one and the routing uses the CNAME value, so this can skip the expected TLS configuration.

### Patches

Traefik v2.6.x: https://github.com/traefik/traefik/releases/tag/v2.6.1

### Workarounds

Add the FDQN to the host rule:

Example:

```yml
  whoami:
    image: traefik/whoami:v1.7.1
    labels:
      traefik.http.routers.whoami.rule: Host(`whoami.example.com`, `whoami.example.com.`)
      traefik.http.routers.whoami.tls: true
      traefik.http.routers.whoami.tls.options: mtls@file
```

There is no workaround if the CNAME flattening is enabled.

### For more information

If you have any questions or comments about this advisory, please [open an issue](https://github.com/traefik/traefik/issues).

