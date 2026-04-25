# LiteLLM has Server-Side Template Injection vulnerability in /completions endpoint

**GHSA**: GHSA-46cm-pfwv-cgf8 | **CVE**: CVE-2024-2952 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-76

**Affected Packages**:
- **litellm** (pip): < 1.34.42

## Description

BerriAI/litellm is vulnerable to Server-Side Template Injection (SSTI) via the `/completions` endpoint. The vulnerability arises from the `hf_chat_template` method processing the `chat_template` parameter from the `tokenizer_config.json` file through the Jinja template engine without proper sanitization. Attackers can exploit this by crafting malicious `tokenizer_config.json` files that execute arbitrary code on the server.
