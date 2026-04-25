# mholt/archiver Vulnerable to Path Traversal via Crafted ZIP File

**GHSA**: GHSA-7vpp-9cxj-q8gv | **CVE**: CVE-2025-3445 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/mholt/archiver** (go): <= 3.5.1
- **github.com/mholt/archiver/v3** (go): <= 3.5.1

## Description

A Path Traversal "Zip Slip" vulnerability has been identified in mholt/archiver in Go. This vulnerability allows using a crafted ZIP file containing path traversal symlinks to create or overwrite files with the user's privileges or application utilizing the library.

When using the archiver.Unarchive functionality with ZIP files, like this: archiver.Unarchive(zipFile, outputDir),  A crafted ZIP file can be extracted in such a way that it writes files to the affected system with the same privileges as the application executing this vulnerable functionality. Consequently, sensitive files may be overwritten, potentially leading to privilege escalation, code execution, and other severe outcomes in some cases.

It's worth noting that a similar vulnerability was found in TAR files (CVE-2024-0406). Although a fix was implemented, it hasn't been officially released, and the affected project has since been deprecated. The successor to mholt/archiver is a new project called mholt/archives, and its initial release (v0.1.0) removes the Unarchive() functionality.
