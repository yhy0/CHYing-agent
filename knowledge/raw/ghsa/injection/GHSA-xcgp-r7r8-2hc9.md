# Gradio's CI vulnerable to Command Injection

**GHSA**: GHSA-xcgp-r7r8-2hc9 | **CVE**: CVE-2024-1540 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-77

**Affected Packages**:
- **gradio** (pip): < 4.18.0

## Description

A command injection vulnerability exists in the deploy+test-visual.yml workflow of the gradio-app/gradio repository, due to improper neutralization of special elements used in a command. This vulnerability allows attackers to execute unauthorized commands, potentially leading to unauthorized modification of the base repository or secrets exfiltration. The issue arises from the unsafe handling of GitHub context information within a an action definition which is evaluated and substituted before script execution. Remediation involves setting untrusted input values to intermediate environment variables to prevent direct influence on script generation.
