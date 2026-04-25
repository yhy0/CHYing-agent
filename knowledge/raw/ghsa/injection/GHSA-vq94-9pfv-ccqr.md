# SQL injection in Apache Traffic Control

**GHSA**: GHSA-vq94-9pfv-ccqr | **CVE**: CVE-2024-45387 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/apache/trafficcontrol/v8** (go): >= 8.0.0, < 8.0.2

## Description

An SQL injection vulnerability in Traffic Ops in Apache Traffic Control <= 8.0.1, >= 8.0.0 allows a privileged user with role "admin", "federation", "operations", "portal", or "steering" to execute arbitrary SQL against the database by sending a specially-crafted PUT request.

Users are recommended to upgrade to version Apache Traffic Control 8.0.2 if you run an affected version of Traffic Ops.
