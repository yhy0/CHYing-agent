# Path Traversal in Buildah

**GHSA**: GHSA-fx8w-mjvm-hvpc | **CVE**: CVE-2020-10696 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/containers/buildah** (go): < 1.14.4

## Description

A path traversal flaw was found in Buildah in versions before 1.14.5. This flaw allows an attacker to trick a user into building a malicious container image hosted on an HTTP(s) server and then write files to the user's system anywhere that the user has permissions.

### Specific Go Packages Affected
github.com/containers/buildah/imagebuildah
