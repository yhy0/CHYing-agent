# JinJava Bypass through ForTag leads to Arbitrary Java Execution

**GHSA**: GHSA-gjx9-j8f8-7j74 | **CVE**: CVE-2026-25526 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-1336

**Affected Packages**:
- **com.hubspot.jinjava:jinjava** (maven): >= 2.8.0, < 2.8.3
- **com.hubspot.jinjava:jinjava** (maven): < 2.7.6

## Description

## Impact

**Vulnerability Type**: Sandbox Bypass / Remote Code Execution

**Affected Component**: Jinjava

**Affected Users**:
- Organizations using HubSpot's Jinjava template rendering engine for user-provided template content
- Any system that renders untrusted Jinja templates using HubSpot's Jinjava implementation
- Users with the ability to create or edit custom code templates

**Severity**: **Critical** - allows arbitrary Java class instantiation and file access bypassing built-in sandbox restrictions

**Root Cause**: Multiple security bypass vulnerabilities in Jinjava's sandbox mechanism:

1. **ForTag Property Access Bypass**: The `ForTag` class does not enforce `JinjavaBeanELResolver` restrictions when iterating over object properties using `Introspector.getBeanInfo()` and invoking getter methods via `PropertyDescriptor.getReadMethod()`

2. **Restricted Class Instantiation**: The sandbox's type allowlist can be bypassed by using ObjectMapper to instantiate classes through JSON deserialization, including creating new `JinjavaELContext` and `JinjavaConfig` instances

**Attack Vector**: An attacker with the ability to create or edit Jinja templates can:
- Access arbitrary getter methods on objects in the template context
- Instantiate `ObjectMapper` to enable default typing
- Create arbitrary Java classes by bypassing type allowlists
- Read files from the server filesystem (demonstrated with `/etc/passwd`)
- Potentially execute arbitrary code

## Patches

**Status**: Patched - CVE-2026-25526

Users should upgrade to one of the following versions which contain fixes for this vulnerability:

- **JinJava 2.8.3** or later
- **JinJava 2.7.6** or later

**Fix Components**:

1. **ForTag Security Hardening**
   - Added security checks to `ForTag.renderForCollection()` to enforce `JinjavaBeanELResolver` restrictions
   - Implemented property access validation against restricted properties/methods before invoking getter methods
   - Added checks for restricted class types before introspection

2. **Enhanced Type Validation**
   - Improved validation in `JinjavaBeanELResolver.isRestrictedClass()` to prevent instantiation of sensitive types
   - Added additional restricted types to the denylist
   - Implemented deeper validation for types created via ObjectMapper deserialization

3. **Configuration Protection**
   - Added checks to prevent creation of new `JinjavaConfig` or `JinjavaELContext` instances via ObjectMapper
   - Prevented modification of `readOnlyResolver` configuration from untrusted templates
   - Implemented additional safeguards around ELResolver configuration

4. **Collection Type Validation**
   - Implemented proper type validation in `HubLELResolver` to prevent collection type wrapping bypasses
   - Added checks for wrapped types in collection deserialization
   - Implemented validation for all types within collections against allowlists

5. **ObjectMapper Restrictions**
   - Added additional restrictions on `ObjectMapper.enableDefaultTyping()` to prevent enabling via less restrictive ELResolver
   - Ensured default typing cannot be enabled without proper authorization

**Information for Users**: Upgrade to version 2.8.3 or 2.7.6 or later to address this vulnerability.

## References

### Project Resources
- **Jinjava Source Code**: [github.com/HubSpot/jinjava](https://github.com/HubSpot/jinjava)
- **Jinjava Releases**: [github.com/HubSpot/jinjava/releases](https://github.com/HubSpot/jinjava/releases)

### Security Standards & Classifications
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-913**: Improper Control of Dynamically-Managed Code Resources
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CVSS v3.1**: Common Vulnerability Scoring System

### Additional Resources
- [OWASP Template Injection](https://owasp.org/www-community/attacks/Server_Side_Template_Injection)
- [Java Deserialization Security](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CVE Standards and Procedures](https://cve.mitre.org/)
