# qdrant input validation failure 

**GHSA**: GHSA-7m75-x27w-r52r | **CVE**: CVE-2024-3829 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-20, CWE-59

**Affected Packages**:
- **qdrant-client** (pip): < 1.9.0

## Description

qdrant/qdrant version 1.9.0-dev is vulnerable to arbitrary file read and write during the snapshot recovery process. Attackers can exploit this vulnerability by manipulating snapshot files to include symlinks, leading to arbitrary file read by adding a symlink that points to a desired file on the filesystem and arbitrary file write by including a symlink and a payload file in the snapshot's directory structure. This vulnerability allows for the reading and writing of arbitrary files on the server, which could potentially lead to a full takeover of the system. The issue is fixed in version v1.9.0.
