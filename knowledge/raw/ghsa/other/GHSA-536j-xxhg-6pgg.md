# Duplicate Advisory: NVIDIA Container Toolkit contains a Time-of-check Time-of-Use (TOCTOU) vulnerability

**GHSA**: GHSA-536j-xxhg-6pgg | **CVE**: N/A | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-367

**Affected Packages**:
- **github.com/NVIDIA/nvidia-container-toolkit** (go): < 1.16.2

## Description

## Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-mjjw-553x-87pq. This link is maintained to preserve external references.

## Original Description
NVIDIA Container Toolkit 1.16.1 or earlier contains a Time-of-check Time-of-Use (TOCTOU) vulnerability when used with default configuration where a specifically crafted container image may gain access to the host file system. This does not impact use cases where CDI is used. A successful exploit of this vulnerability may lead to code execution, denial of service, escalation of privileges, information disclosure, and data tampering.
