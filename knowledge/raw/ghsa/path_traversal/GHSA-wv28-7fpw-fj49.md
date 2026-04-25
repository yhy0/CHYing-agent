# Lektor does not sanitize database path traversal

**GHSA**: GHSA-wv28-7fpw-fj49 | **CVE**: CVE-2024-28335 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-22

**Affected Packages**:
- **Lektor** (pip): >= 0, < 3.3.11
- **Lektor** (pip): >= 3.4.0b1, < 3.4.0b11

## Description

Lektor before 3.3.11 does not sanitize DB path traversal. Thus, shell commands might be executed via a file that is added to the templates directory, if the victim's web browser accesses an untrusted website that uses JavaScript to send requests to localhost port 5000, and the web browser is running on the same machine as the "lektor server" command.
