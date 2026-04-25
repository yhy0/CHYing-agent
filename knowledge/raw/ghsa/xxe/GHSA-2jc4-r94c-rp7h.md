# Apache Ivy External Entity Reference vulnerability

**GHSA**: GHSA-2jc4-r94c-rp7h | **CVE**: CVE-2022-46751 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-91, CWE-611

**Affected Packages**:
- **org.apache.ivy:ivy** (maven): < 2.5.2

## Description

Improper Restriction of XML External Entity Reference, XML Injection (aka Blind XPath Injection) vulnerability in Apache Software Foundation Apache Ivy.This issue affects any version of Apache Ivy prior to 2.5.2.

When Apache Ivy prior to 2.5.2 parses XML files - either its own configuration, Ivy files or Apache Maven POMs - it will allow downloading external document type definitions and expand any entity references contained therein when used.

This can be used to exfiltrate data, access resources only the machine running Ivy has access to or disturb the execution of Ivy in different ways.

Starting with Ivy 2.5.2 DTD processing is disabled by default except when parsing Maven POMs where the default is to allow DTD processing but only to include a DTD snippet shipping with Ivy that is needed to deal with existing Maven POMs that are not valid XML files but are nevertheless accepted by Maven. Access can be be made more lenient via newly introduced system properties where needed.

Users of Ivy prior to version 2.5.2 can use Java system properties to restrict processing of external DTDs, see the section about "JAXP Properties for External Access restrictions" inside Oracle's "Java API for XML Processing (JAXP) Security Guide".
