# mastercactapus proxyprotocol vulnerable to denial of service

**GHSA**: GHSA-85c5-ccm8-vr96 | **CVE**: CVE-2019-14243 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-20

**Affected Packages**:
- **github.com/mastercactapus/proxyprotocol** (go): < 0.0.2

## Description

headerv2.go in mastercactapus proxyprotocol before 0.0.2, as used in the mastercactapus caddy-proxyprotocol plugin through 0.0.2 for Caddy, allows remote attackers to cause a denial of service (webserver panic and daemon crash) via a crafted HAProxy PROXY v2 request with truncated source/destination address data.
