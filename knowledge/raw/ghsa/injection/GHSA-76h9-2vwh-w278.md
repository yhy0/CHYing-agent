# Apache MINA Deserialization RCE Vulnerability

**GHSA**: GHSA-76h9-2vwh-w278 | **CVE**: CVE-2024-52046 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94, CWE-502

**Affected Packages**:
- **org.apache.mina:mina-core** (maven): >= 2.2.0, < 2.2.4
- **org.apache.mina:mina-core** (maven): >= 2.1.0, < 2.1.10
- **org.apache.mina:mina-core** (maven): >= 2.0.0-M1, < 2.0.27

## Description

The `ObjectSerializationDecoder` in Apache MINA uses Java’s native deserialization protocol to process incoming serialized data but lacks the necessary security checks and defenses. This vulnerability allows attackers to exploit the deserialization process by sending specially crafted malicious serialized data, potentially leading to remote code execution (RCE) attacks.
	
This issue affects MINA core versions 2.0.X, 2.1.X and 2.2.X, and will be fixed by the releases 2.0.27, 2.1.10 and 2.2.4.

It's also important to note that an application using MINA core library will only be affected if the IoBuffer#getObject() method is called, and this specific method is potentially called when adding a ProtocolCodecFilter instance using the `ObjectSerializationCodecFactory` class in the filter chain. If your application is specifically using those classes, you have to upgrade to the latest version of MINA core library.

Upgrading will  not be enough: you also need to explicitly allow the classes the decoder will accept in the ObjectSerializationDecoder instance, using one of the three new methods:

1. 
     * Accept class names where the supplied ClassNameMatcher matches for deserialization, unless they are otherwise rejected.
     * `@param classNameMatcher` the matcher to use
     * / `public void accept(ClassNameMatcher classNameMatcher)`

2. 
     * Accept class names that match the supplied pattern for deserialization, unless they are otherwise rejected.
     * `@param` pattern standard Java regexp
     * / `public void accept(Pattern pattern)`

3.
     * Accept the wildcard specified classes for deserialization, unless they are otherwise rejected.
     * `@param` patterns Wildcard file name patterns as defined by `{@link org.apache.commons.io.FilenameUtils#wildcardMatch(String, String) FilenameUtils.wildcardMatch}`
     * / `public void accept(String... patterns)`

By default, the decoder will reject *all* classes that will be present in the incoming data.

Note: The FtpServer, SSHd and Vysper sub-project are not affected by this issue.
