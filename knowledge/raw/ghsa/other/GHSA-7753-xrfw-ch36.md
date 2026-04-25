# LlamaIndex affected by a Denial of Service (DOS) in JSONReader

**GHSA**: GHSA-7753-xrfw-ch36 | **CVE**: CVE-2025-5302 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-674

**Affected Packages**:
- **llama-index-core** (pip): < 0.12.38

## Description

A denial of service vulnerability exists in the JSONReader component of the run-llama/llama_index repository, specifically in version v0.12.37. The vulnerability is caused by uncontrolled recursion when parsing deeply nested JSON files, which can lead to Python hitting its maximum recursion depth limit. This results in high resource consumption and potential crashes of the Python process. The issue is resolved in version 0.12.38.
