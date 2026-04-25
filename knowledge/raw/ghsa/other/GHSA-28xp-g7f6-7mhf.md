# Syncthing vulnerable to symlink traversal and arbitrary file overwrite

**GHSA**: GHSA-28xp-g7f6-7mhf | **CVE**: CVE-2017-1000420 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-59

**Affected Packages**:
- **github.com/syncthing/syncthing** (go): <= 0.14.33

## Description

Syncthing version 0.14.33 and older erronously versions symlinks when they are deleted. If a directory is then created with the same name, a file created in that directory, and the file deleted, it is moved into the symlink target. This can lead to symlink traversal resulting in arbitrary file overwrite.
