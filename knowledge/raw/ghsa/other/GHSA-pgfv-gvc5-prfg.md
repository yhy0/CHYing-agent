# Gradio Vulnerable to Arbitrary File Deletion

**GHSA**: GHSA-pgfv-gvc5-prfg | **CVE**: CVE-2024-10648 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-29

**Affected Packages**:
- **gradio** (pip): >= 4.0.0, <= 5.0.0b2

## Description

A path traversal vulnerability exists in the Gradio Audio component of gradio-app/gradio, as of version git 98cbcae. This vulnerability allows an attacker to control the format of the audio file, leading to arbitrary file content deletion. By manipulating the output format, an attacker can reset any file to an empty file, causing a denial of service (DOS) on the server.
