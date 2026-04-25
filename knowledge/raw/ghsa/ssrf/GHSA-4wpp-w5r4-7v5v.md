# Server-Side Request Forgery in charm

**GHSA**: GHSA-4wpp-w5r4-7v5v | **CVE**: CVE-2022-29180 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-918

**Affected Packages**:
- **github.com/charmbracelet/charm** (go): >= 0.9.0, < 0.12.1

## Description

We've discovered a vulnerability in which attackers could forge HTTP requests to manipulate the `charm` data directory to access or delete anything on the server. This has been patched in https://github.com/charmbracelet/charm/commit/3c90668f955c7ce5ef721e4fc9faee7053232fd3 and is available in release [v0.12.1](https://github.com/charmbracelet/charm/releases/tag/v0.12.1). We recommend that all users running self-hosted `charm` instances update immediately.

This vulnerability was found in-house and we haven't been notified of any potential exploiters.

### Additional notes

* Encrypted user data uploaded to the Charm server is safe as Charm servers cannot decrypt user data. This includes filenames, paths, and all key-value data.
* Users running the official Charm [Docker images](https://github.com/charmbracelet/charm/blob/main/docker.md) are at minimal risk because the exploit is limited to the containerized filesystem.

### For more information

If you have any questions or comments about this advisory:
* Open a [discussion](https://github.com/charmbracelet/charm/discussions)
* Email us at [vt100@charm.sh](mailto:vt100@charm.sh)
* Chat with us on [Slack](https://charm.sh/slack)

* * *

<a href="https://charm.sh/"><img alt="the Charm logo" src="https://stuff.charm.sh/charm-badge.jpg" width="400"></a>

Charm热爱开源 • Charm loves open source
