# Remote Command Execution in SOFARPC

**GHSA**: GHSA-7q8p-9953-pxvr | **CVE**: CVE-2024-23636 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **com.alipay.sofa:rpc-sofa-boot-starter** (maven): < 5.12.0

## Description

Impact
SOFARPC defaults to using the SOFA Hessian protocol to deserialize received data, while the SOFA Hessian protocol uses a blacklist mechanism to restrict deserialization of potentially dangerous classes for security protection. But there is a gadget chain that can bypass the SOFA Hessian blacklist protection mechanism, and this gadget chain only relies on JDK and does not rely on any third-party components.

Patches
Fixed this issue by adding a blacklist, users can upgrade to sofarpc version 5.12.0 to avoid this issue.

Workarounds
SOFARPC also provides a way to add additional blacklist. Users can add some class like -Drpc_serialize_blacklist_override=org.apache.xpath. to avoid this issue.
