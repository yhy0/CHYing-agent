# Vanna prompt injection code execution

**GHSA**: GHSA-7735-w2jp-gvg6 | **CVE**: CVE-2024-5565 | **Severity**: critical (CVSS 8.1)

**CWE**: CWE-77, CWE-94

**Affected Packages**:
- **vanna** (pip): <= 0.5.5

## Description

The Vanna library uses a prompt function to present the user with visualized results, it is possible to alter the prompt using prompt injection and run arbitrary Python code instead of the intended visualization code. Specifically - allowing external input to the library’s “ask” method with "visualize" set to True (default behavior) leads to remote code execution.
