# melange QEMU runner could write files outside workspace directory

**GHSA**: GHSA-qxx2-7h4c-83f4 | **CVE**: CVE-2026-24843 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-22

**Affected Packages**:
- **chainguard.dev/melange** (go): >= 0.11.3, < 0.40.3

## Description

An attacker who can influence the tar stream from a QEMU guest VM could write files outside the intended workspace directory on the host. The `retrieveWorkspace` function extracts tar entries without validating that paths stay within the workspace, allowing Path Traversal via `../` sequences.

**Fix:** Fixed in [6e243d0d](https://github.com/chainguard-dev/melange/commit/6e243d0d46699f837d7c392397a694d2bcc7612b). Merged in release.

**Acknowledgements**

melange thanks Oleh Konko from [1seal](https://1seal.org/) for discovering and reporting this issue.
