# github.com/kumahq/kuma affected by CVE-2023-44487

**GHSA**: GHSA-9wmc-rg4h-28wv | **CVE**: N/A | **Severity**: high (CVSS 7.5)

**CWE**: N/A

**Affected Packages**:
- **github.com/kumahq/kuma** (go): >= 2.4.0, < 2.4.3
- **github.com/kumahq/kuma** (go): >= 2.3.0, < 2.3.3
- **github.com/kumahq/kuma** (go): >= 2.2.0, < 2.2.4
- **github.com/kumahq/kuma** (go): >= 2.1.0, < 2.1.8
- **github.com/kumahq/kuma** (go): < 2.0.8

## Description

### Impact
Envoy and Go HTTP/2 protocol stack is vulnerable to the "Rapid Reset" class of exploits, which send a sequence of HEADERS frames optionally followed by RST_STREAM frames.

This can be exercised if you use the builtin gateway and receive untrusted http2 traffic.

### Patches

https://github.com/kumahq/kuma/pull/8023
https://github.com/kumahq/kuma/pull/8001
https://github.com/kumahq/kuma/pull/8034

### Workarounds
Disable http2 on the gateway listener with a MeshProxyPatch or ProxyTemplate.

### References
https://github.com/advisories/GHSA-qppj-fm5r-hxr3
https://github.com/golang/go/issues/63417
https://github.com/envoyproxy/envoy/security/advisories/GHSA-jhv4-f7mr-xx76
https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack
https://www.nginx.com/blog/http-2-rapid-reset-attack-impacting-f5-nginx-products/?sf269548684=1
https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge
