# vLLM has remote code execution vulnerability in the tool call parser for Qwen3-Coder

**GHSA**: GHSA-79j6-g2m3-jgfw | **CVE**: CVE-2025-9141 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **vllm** (pip): >= 0.10.0, < 0.10.1.1

## Description

### Summary
An unsafe deserialization vulnerability allows any authenticated user to execute arbitrary code on the server if they are able to get the model to pass the code as an argument to a tool call.

### Details
 vLLM's [Qwen3 Coder tool parser](https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/openai/tool_parsers/qwen3coder_tool_parser.py) contains a code execution path that uses Python's `eval()` function to parse tool call parameters. This occurs during the parameter conversion process when the parser attempts to handle unknown data types.

This code path is reached when:
1. Tool calling is enabled (`--enable-auto-tool-choice`)
2. The qwen3_coder parser is specified (`--tool-call-parser qwen3_coder`)
3. The parameter type is not explicitly defined or recognized

### Impact
Remote Code Execution via Python's `eval()` function.
