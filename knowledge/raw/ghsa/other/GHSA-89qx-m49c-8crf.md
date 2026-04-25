# Ollama Allows Out-of-Bounds Read

**GHSA**: GHSA-89qx-m49c-8crf | **CVE**: CVE-2024-12055 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-125

**Affected Packages**:
- **github.com/ollama/ollama** (go): <= 0.3.14

## Description

A vulnerability in Ollama versions <=0.3.14 allows a malicious user to create a customized gguf model file that can be uploaded to the public Ollama server. When the server processes this malicious model, it crashes, leading to a Denial of Service (DoS) attack. The root cause of the issue is an out-of-bounds read in the gguf.go file.
