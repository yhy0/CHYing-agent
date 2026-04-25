# Prometheus vulnerable to basic authentication bypass

**GHSA**: GHSA-4v48-4q5m-8vx4 | **CVE**: N/A | **Severity**: high (CVSS 7.2)

**CWE**: CWE-303

**Affected Packages**:
- **github.com/prometheus/prometheus** (go): >= 2.24.1, < 2.37.4
- **github.com/prometheus/prometheus** (go): >= 2.38.0, < 2.40.4
- **github.com/prometheus/prometheus/v2** (go): >= 2.24.1, < 2.37.4
- **github.com/prometheus/prometheus/v2** (go): >= 2.38.0, < 2.40.4

## Description

### Impact

Prometheus can be secured by a web.yml file that specifies usernames and hashed passwords for basic authentication.

Passwords are hashed with bcrypt, which means that even if you have access to the hash, it is very hard to find the original password back.

However, a flaw in the way this mechanism was implemented in the [exporter toolkit](https://github.com/prometheus/exporter-toolkit) makes it possible with people who know the hashed password to authenticate against Prometheus.

A request can be forged by an attacker to poison the internal cache used to cache the computation of hashes and make subsequent requests successful. This cache is used in both happy and unhappy scenarios in order to limit side channel attacks that could tell an attacker if a user is present in the file or not.

### Patches

Prometheus 2.37.4 ([LTS](https://prometheus.io/docs/introduction/release-cycle/)) and 2.40.4 have been released to address this issue.

### Workarounds

There is no workaround but attacker must have access to the hashed password, stored in disk, to bypass the authentication.
