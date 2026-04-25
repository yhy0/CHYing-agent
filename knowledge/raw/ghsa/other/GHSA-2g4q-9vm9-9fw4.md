# Jenkins Script Security Plugin sandbox bypass vulnerability

**GHSA**: GHSA-2g4q-9vm9-9fw4 | **CVE**: CVE-2024-34145 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-290

**Affected Packages**:
- **org.jenkins-ci.plugins:script-security** (maven): < 1336.vf33a

## Description

Jenkins Script Security Plugin provides a sandbox feature that allows low privileged users to define scripts, including Pipelines, that are generally safe to execute. Calls to code defined inside a sandboxed script are intercepted, and various allowlists are checked to determine whether the call is to be allowed.

Multiple sandbox bypass vulnerabilities exist in Script Security Plugin 1335.vf07d9ce377a_e and earlier:

- Crafted constructor bodies that invoke other constructors can be used to construct any subclassable type via implicit casts.

- Sandbox-defined Groovy classes that shadow specific non-sandbox-defined classes can be used to construct any subclassable type.

These vulnerabilities allow attackers with permission to define and run sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the context of the Jenkins controller JVM.
