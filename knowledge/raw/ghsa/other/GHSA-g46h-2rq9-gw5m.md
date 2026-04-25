# OpenBao has potential Denial of Service vulnerability when processing malicious unauthenticated JSON requests

**GHSA**: GHSA-g46h-2rq9-gw5m | **CVE**: CVE-2025-59043 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/openbao/openbao** (go): <= 2.4.0

## Description

### Summary

JSON objects after decoding might use more memory than their serialized version. It is possible to tune a JSON to maximize the factor between serialized memory usage and deserialized memory usage (similar to a zip bomb). While reproducing the issue, we could reach a factor of about 35. This can be used to circumvent the [`max_request_size` (https://openbao.org/docs/configuration/listener/tcp/) configuration parameter, which is meant to protect against Denial of Service attacks, and also makes Denial of Service attacks easier in general, as the attacker needs much less resources.

### Details

The request body is parsed into a `map[string]interface{}` https://github.com/openbao/openbao/blob/788536bd3e10818a7b4fb00aac6affc23388e5a9/http/logical.go#L50 very early in the request handling chain (before authentication), which means an attacker can send a specifically crafted JSON object and cause an OOM crash. Additionally, for simpler requests with large numbers of strings, the audit subsystem can consume large quantities of CPU. 

To remediate, set `max_request_json_memory` and `max_request_json_strings`.

### Impact

- Unauthenticated Denial of Service

### Resources

This issue was disclosed directly to HashiCorp and is the OpenBao equivalent of the following tickets:

- https://discuss.hashicorp.com/t/hcsec-2025-24-vault-denial-of-service-though-complex-json-payloads/76393
- https://nvd.nist.gov/vuln/detail/CVE-2025-6203

HashiCorp attributes the problem to the audit subsystem. For OpenBao, it was noted the problem was additionally in the requests handling logic.
