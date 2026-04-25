# Aim Web API vulnerable to Remote Code Execution

**GHSA**: GHSA-mxvw-cj37-8g2h | **CVE**: CVE-2024-2195 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **aim** (pip): >= 3.0.0, <= 3.25.0

## Description

A critical Remote Code Execution (RCE) vulnerability was identified in the aimhubio/aim project, specifically within the `/api/runs/search/run/` endpoint, affecting versions >= 3.0.0. The vulnerability resides in the `run_search_api` function of the `aim/web/api/runs/views.py` file, where improper restriction of user access to the `RunView` object allows for the execution of arbitrary code via the `query` parameter. This issue enables attackers to execute arbitrary commands on the server, potentially leading to full system compromise.
