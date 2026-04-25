# Unstructured has Path Traversal via Malicious MSG Attachment that Allows Arbitrary File Write

**GHSA**: GHSA-gm8q-m8mv-jj5m | **CVE**: CVE-2025-64712 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22, CWE-73

**Affected Packages**:
- **unstructured** (pip): <= 0.18.17

## Description

A Path Traversal vulnerability in the `partition_msg` function allows an attacker to write or overwrite arbitrary files on the filesystem when processing malicious MSG files with attachments.

  ## Impact
  An attacker can craft a malicious .msg file with attachment filenames containing path traversal sequences (e.g.,
  `../../../etc/cron.d/malicious`). When processed with `process_attachments=True`, the library writes the attachment to an
  attacker-controlled path, potentially leading to:

  - Arbitrary file overwrite
  - Remote code execution (via overwriting configuration files, cron jobs, or Python packages)
  - Data corruption
  - Denial of service

  ## Affected Functionality
  The vulnerability affects the MSG file partitioning functionality when `process_attachments=True` is enabled.

  ## Vulnerability Details
  The library does not sanitize attachment filenames in MSG files before using them in file write operations, allowing directory
  traversal sequences to escape the intended output directory.

  ## Workarounds
  Until patched, users can:
  - Set `process_attachments=False` when processing untrusted MSG files
  - Avoid processing MSG files from untrusted sources
  - Implement additional filename validation before processing
