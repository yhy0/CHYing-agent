# Aim  path traversal in LockManager.release_locks

**GHSA**: GHSA-4qcx-jx49-6qrh | **CVE**: CVE-2024-8769 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-22, CWE-29

**Affected Packages**:
- **aim** (pip): >= 3.15.0, <= 3.27.0

## Description

A vulnerability in the `LockManager.release_locks` function in aimhubio/aim (commit bb76afe) allows for arbitrary file deletion through relative path traversal. The `run_hash` parameter, which is user-controllable, is concatenated without normalization as part of a path used to specify file deletion. This vulnerability is exposed through the `Repo._close_run()` method, which is accessible via the tracking server instruction API. As a result, an attacker can exploit this to delete any arbitrary file on the machine running the tracking server.
