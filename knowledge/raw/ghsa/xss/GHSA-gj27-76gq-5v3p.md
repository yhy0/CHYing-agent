# Open WebUI stored cross-site scripting (XSS) vulnerability

**GHSA**: GHSA-gj27-76gq-5v3p | **CVE**: CVE-2024-7990 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-79

**Affected Packages**:
- **open-webui** (pip): <= 0.3.8

## Description

A stored cross-site scripting (XSS) vulnerability exists in open-webui/open-webui version 0.3.8. The vulnerability is present in the `/api/v1/models/add` endpoint, where the model description field is improperly sanitized before being rendered in chat. This allows an attacker to inject malicious scripts that can be executed by any user, including administrators, potentially leading to arbitrary code execution.
