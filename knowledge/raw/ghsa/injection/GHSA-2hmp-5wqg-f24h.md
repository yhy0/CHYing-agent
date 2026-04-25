# PlotAI eval vulnerability

**GHSA**: GHSA-2hmp-5wqg-f24h | **CVE**: CVE-2025-1497 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-77, CWE-94

**Affected Packages**:
- **plotai** (pip): < 0.0.7

## Description

A vulnerability, that could result in Remote Code Execution (RCE), has been found in PlotAI. Lack of validation of LLM-generated output allows attacker to execute arbitrary Python code. PlotAI commented out vulnerable line, further usage of the software requires uncommenting it and thus accepting the risk.
