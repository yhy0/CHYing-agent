# Kedro deserialization vulnerability

**GHSA**: GHSA-747f-ww56-4q4h | **CVE**: CVE-2024-9701 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **kedro** (pip): < 0.19.9

## Description

A Remote Code Execution (RCE) vulnerability has been identified in the Kedro ShelveStore class (version 0.19.8). This vulnerability allows an attacker to execute arbitrary Python code via deserialization of malicious payloads, potentially leading to a full system compromise. The ShelveStore class uses Python's shelve module to manage session data, which relies on pickle for serialization. Crafting a malicious payload and storing it in the shelve file can lead to RCE when the payload is deserialized.
