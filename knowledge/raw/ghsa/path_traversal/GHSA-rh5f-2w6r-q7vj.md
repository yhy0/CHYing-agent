# Podman Path Traversal Vulnerability leads to arbitrary file read/write

**GHSA**: GHSA-rh5f-2w6r-q7vj | **CVE**: CVE-2019-10152 | **Severity**: high (CVSS 7.2)

**CWE**: CWE-22, CWE-59

**Affected Packages**:
- **github.com/containers/podman** (go): < 1.4.0

## Description

A path traversal vulnerability has been discovered in podman before version 1.4.0 in the way it handles symlinks inside containers. An attacker who has compromised an existing container can cause arbitrary files on the host filesystem to be read/written when an administrator tries to copy a file from/to the container.
