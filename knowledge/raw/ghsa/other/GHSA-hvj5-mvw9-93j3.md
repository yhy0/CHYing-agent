# Insecure deserialization in BentoML

**GHSA**: GHSA-hvj5-mvw9-93j3 | **CVE**: CVE-2024-2912 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-1188

**Affected Packages**:
- **bentoml** (pip): < 1.2.5

## Description

An insecure deserialization vulnerability exists in the BentoML framework, allowing remote code execution (RCE) by sending a specially crafted POST request. By exploiting this vulnerability, attackers can execute arbitrary commands on the server hosting the BentoML application. The vulnerability is triggered when a serialized object, crafted to execute OS commands upon deserialization, is sent to any valid BentoML endpoint. This issue poses a significant security risk, enabling attackers to compromise the server and potentially gain unauthorized access or control.
