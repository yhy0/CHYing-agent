# Juju's unprivileged user running on charm node can leak any secret or relation data accessible to the local charm

**GHSA**: GHSA-6vjm-54vp-mxhx | **CVE**: N/A | **Severity**: high (CVSS 8.8)

**CWE**: CWE-209, CWE-269, CWE-284

**Affected Packages**:
- **github.com/juju/juju** (go): < 2.9.50
- **github.com/juju/juju** (go): >= 3.0.0, < 3.1.9
- **github.com/juju/juju** (go): >= 3.2.0, < 3.3.6
- **github.com/juju/juju** (go): >= 3.4.0, < 3.4.5
- **github.com/juju/juju** (go): >= 3.5.0, < 3.5.3

## Description

An issue was discovered in Juju that resulted in the leak of the sensitive context ID, which allows a local unprivileged attacker to access other sensitive data or relation accessible to the local charm. A potential exploit where a user can run a bash loop attempting to execute hook tools. If running while another hook is executing, we log an error with the context ID, making it possible for the user to then use that ID in a following call successfully. This means an unprivileged user can access anything available via a hook tool such as config, relation data and secrets.
