# Authz zero length regression

**GHSA**: GHSA-v23v-6jw2-98fq | **CVE**: CVE-2024-41110 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-187

**Affected Packages**:
- **github.com/docker/docker** (go): >= 24.0.0, < 25.0.6
- **github.com/docker/docker** (go): >= 19.03.0, < 23.0.15
- **github.com/docker/docker** (go): >= 26.0.0, < 26.1.5
- **github.com/docker/docker** (go): >= 27.0.0, < 27.1.1

## Description

A security vulnerability has been detected in certain versions of Docker Engine, which could allow an attacker to bypass [authorization plugins (AuthZ)](https://docs.docker.com/engine/extend/plugins_authorization/) under specific circumstances. The base likelihood of this being exploited is low. This advisory outlines the issue, identifies the affected versions, and provides remediation steps for impacted users.

### Impact

Using a specially-crafted API request, an Engine API client could make the daemon forward the request or response to an [authorization plugin](https://docs.docker.com/engine/extend/plugins_authorization/) without the body. In certain circumstances, the authorization plugin may allow a request which it would have otherwise denied if the body had been forwarded to it.


A security issue was discovered In 2018,  where an attacker could bypass AuthZ plugins using a specially crafted API request. This could lead to unauthorized actions, including privilege escalation. Although this issue was fixed in Docker Engine [v18.09.1](https://docs.docker.com/engine/release-notes/18.09/#security-fixes-1) in January 2019, the fix was not carried forward to later major versions, resulting in a regression. Anyone who depends on authorization plugins that introspect the request and/or response body to make access control decisions is potentially impacted.

Docker EE v19.03.x and all versions of Mirantis Container Runtime **are not vulnerable.**

### Vulnerability details

- **AuthZ bypass and privilege escalation:** An attacker could exploit a bypass using an API request with Content-Length set to 0, causing the Docker daemon to forward the request without the body to the AuthZ plugin, which might approve the request incorrectly.
- **Initial fix:** The issue was fixed in Docker Engine [v18.09.1](https://docs.docker.com/engine/release-notes/18.09/#security-fixes-1) January 2019..
- **Regression:** The fix was not included in Docker Engine v19.03 or newer versions. This was identified in April 2024 and patches were released for the affected versions on July 23, 2024. The issue was assigned [CVE-2024-41110](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-41110).

### Patches

- docker-ce v27.1.1 containes patches to fix the vulnerability.
- Patches have also been merged into the master, 19.0, 20.0, 23.0, 24.0, 25.0, 26.0, and 26.1 release branches.

### Remediation steps

- If you are running an affected version, update to the most recent patched version.
- Mitigation if unable to update immediately:
    - Avoid using AuthZ plugins.
    - Restrict access to the Docker API to trusted parties, following the principle of least privilege.


### References

- https://github.com/moby/moby/commit/fc274cd2ff4cf3b48c91697fb327dd1fb95588fb
- https://github.com/moby/moby/commit/a79fabbfe84117696a19671f4aa88b82d0f64fc1
- https://www.docker.com/blog/docker-security-advisory-docker-engine-authz-plugin/
