# Incorrect Permission Assignment for Critical Resource in Singularity

**GHSA**: GHSA-557g-r22w-9wvx | **CVE**: CVE-2019-11328 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-269, CWE-732

**Affected Packages**:
- **github.com/sylabs/singularity** (go): >= 3.1.0, < 3.2.0

## Description

An issue was discovered in Singularity 3.1.0 to 3.2.0-rc2, a malicious user with local/network access to the host system (e.g. ssh) could exploit this vulnerability due to insecure permissions allowing a user to edit files within `/run/singularity/instances/sing/<user>/<instance>`. The manipulation of those files can change the behavior of the starter-suid program when instances are joined resulting in potential privilege escalation on the host.
