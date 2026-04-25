# apko has a path traversal in apko dirFS which allows filesystem writes outside base

**GHSA**: GHSA-5g94-c2wx-8pxw | **CVE**: CVE-2026-25121 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-22, CWE-23

**Affected Packages**:
- **chainguard.dev/apko** (go): >= 0.14.8, < 1.1.0

## Description

A Path Traversal vulnerability was discovered in apko's dirFS filesystem abstraction. An attacker who can supply a malicious APK package (e.g., via a compromised or typosquatted repository) could create directories or symlinks outside the intended installation root. The MkdirAll, Mkdir, and Symlink methods in pkg/apk/fs/rwosfs.go use filepath.Join() without validating that the resulting path stays within the base directory.

**Fix:** Fixed by [d8b7887](https://github.com/chainguard-dev/apko/commit/d8b7887a968a527791b3c591ae83928cb49a9f14). Merged into release. 

**Acknowledgements**                                                                                                                                                                        
                                                                                                                                                                                              
apko thanks Oleh Konko from [1seal](https://1seal.org/) for discovering and reporting this issue.
