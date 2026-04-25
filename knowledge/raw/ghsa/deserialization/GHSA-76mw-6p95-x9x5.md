# pac4j-core affected by a Java deserialization vulnerability

**GHSA**: GHSA-76mw-6p95-x9x5 | **CVE**: CVE-2023-25581 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.pac4j:pac4j-core** (maven): < 4.0.0

## Description

pac4j is a security framework for Java. `pac4j-core` prior to version 4.0.0 is affected by a Java deserialization vulnerability. The vulnerability affects systems that store externally controlled values in attributes of the `UserProfile` class from pac4j-core. It can be exploited by providing an attribute that contains a serialized Java object with a special prefix `{#sb64}` and Base64 encoding. This issue may lead to Remote Code Execution (RCE) in the worst case. Although a `RestrictedObjectInputStream` is in place, that puts some restriction on what classes can be deserialized, it still allows a broad range of java packages and potentially exploitable with different gadget chains. pac4j versions 4.0.0 and greater are not affected by this issue. Users are advised to upgrade. There are no known workarounds for this vulnerability.
