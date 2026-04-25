# litellm vulnerable to remote code execution based on using eval unsafely

**GHSA**: GHSA-gppg-gqw8-wh9g | **CVE**: CVE-2024-5751 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **litellm** (pip): < 1.40.16

## Description

BerriAI/litellm version v1.35.8 contains a vulnerability where an attacker can achieve remote code execution. The vulnerability exists in the `add_deployment` function, which decodes and decrypts environment variables from base64 and assigns them to `os.environ`. An attacker can exploit this by sending a malicious payload to the `/config/update` endpoint, which is then processed and executed by the server when the `get_secret` function is triggered. This requires the server to use Google KMS and a database to store a model.
