# BuildKit vulnerable to possible host system access from mount stub cleaner

**GHSA**: GHSA-4v98-7qmw-rqr8 | **CVE**: CVE-2024-23652 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/moby/buildkit** (go): < 0.12.5

## Description

### Impact
A malicious BuildKit frontend or Dockerfile using `RUN --mount` could trick the feature that removes empty files created for the mountpoints into removing a file outside the container, from the host system.

### Patches
The issue has been fixed in v0.12.5

### Workarounds
Avoid using BuildKit frontend from an untrusted source or building an untrusted Dockerfile containing `RUN --mount` feature.

### References


