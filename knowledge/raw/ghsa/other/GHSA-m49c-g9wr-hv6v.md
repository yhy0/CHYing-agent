# jinjava has Sandbox Bypass via JavaType-Based Deserialization

**GHSA**: GHSA-m49c-g9wr-hv6v | **CVE**: CVE-2025-59340 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-1336

**Affected Packages**:
- **com.hubspot.jinjava:jinjava** (maven): = 2.8.0
- **com.hubspot.jinjava:jinjava** (maven): < 2.7.5

## Description

### Summary

jinjava’s current sandbox restrictions prevent direct access to dangerous methods such as `getClass()`, and block instantiation of Class objects. However, these protections can be bypassed.

By using mapper.getTypeFactory().constructFromCanonical(), it is possible to instruct the underlying ObjectMapper to deserialize attacker-controlled input into arbitrary classes. This enables the creation of semi-arbitrary class instances without directly invoking restricted methods or class literals.

As a result, an attacker can escape the sandbox and instantiate classes such as java.net.URL, opening up the ability to access local files and URLs(e.g., file:///etc/passwd). With further chaining, this primitive can potentially lead to remote code execution (RCE).

### Details

jinjava templates expose a built-in variable `____int3rpr3t3r____`, which provides direct access to the jinjavaInterpreter instance.
This variable was previously abused and protections were added to prevent call method from `JinjavaInterpreter` instances (see [Add interpreter to blacklist](https://github.com/HubSpot/jinjava/commit/1b9aaa4b420c58b4a301cf4b7d26207f1c8d1165)).
However, interacting with the properties of `JinjavaInterpreter` instances remains [unrestricted](https://github.com/HubSpot/jinjava/blob/jinjava-2.8.0/src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java#L80-L84).

From `____int3rpr3t3r____`, it is possible to traverse to the `config` field, which exposes an ObjectMapper. By invoking `readValue(String content, JavaType valueType)` on this ObjectMapper, an attacker can instantiate arbitrary classes specified via `JavaType`.

Although jinjava explicitly restricts dangerous classes such as `Class`, `ClassLoader`, and so on inside `JinjavaBeanELResolver`, the `JavaType` class itself is [not restricted](https://github.com/HubSpot/jinjava/blob/jinjava-2.8.0/src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java#L246-L262). 

As a result, an attacker can leverage `JavaType` construction (`constructFromCanonical`) to instantiate semi-arbitrary classes without directly calling restricted methods.

This allows sandbox escape and the creation of powerful primitives. 

### Impact
Escape the Jinjava sandbox and instantiate a wide range of classes using JavaType.
This capability can be used to read arbitrary files and to perform full read SSRF by creating network-related objects.
In certain environments, depending on the available classes, this primitive can even lead to complete remote code execution.
