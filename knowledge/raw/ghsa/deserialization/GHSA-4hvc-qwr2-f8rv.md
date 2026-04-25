# Redisson vulnerable to Deserialization of Untrusted Data

**GHSA**: GHSA-4hvc-qwr2-f8rv | **CVE**: CVE-2023-42809 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-502

**Affected Packages**:
- **org.redisson:redisson** (maven): < 3.22.0

## Description

Redisson is a Java Redis client that uses the Netty framework. Prior to version 3.22.0, some of the messages received from the Redis server contain Java objects that the client deserializes without further validation. Attackers that manage to trick clients into communicating with a malicious server can include especially crafted objects in its responses that, once deserialized by the client, force it to execute arbitrary code. This can be abused to take control of the machine the client is running in. Version 3.22.0 contains a patch for this issue.

Some post-fix advice is available. Do NOT use `Kryo5Codec` as deserialization codec, as it is still vulnerable to arbitrary object deserialization due to the `setRegistrationRequired(false)` call. On the contrary, `KryoCodec` is safe to use. The fix applied to `SerializationCodec` only consists of adding an optional allowlist of class names, even though making this behavior the default is recommended. When instantiating `SerializationCodec` please use the `SerializationCodec(ClassLoader classLoader, Set<String> allowedClasses)` constructor to restrict the allowed classes for deserialization.
