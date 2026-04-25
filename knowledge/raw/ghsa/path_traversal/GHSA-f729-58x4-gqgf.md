# CometVisu Backend for openHAB affected by RCE through path traversal

**GHSA**: GHSA-f729-58x4-gqgf | **CVE**: CVE-2024-42469 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22

**Affected Packages**:
- **org.openhab.ui.bundles:org.openhab.ui.cometvisu** (maven): <= 4.2.0

## Description

CometVisu's file system endpoints don't require authentication and additionally the endpoint to update an existing file is susceptible to path traversal. This makes it possible for an attacker to overwrite existing files on the openHAB instance. If the overwritten file is a shell script that is executed at a later time this vulnerability can allow remote code execution by an attacker.

This vulnerability was discovered with the help of CodeQL's [Uncontrolled data used in path expression](https://codeql.github.com/codeql-query-help/java/java-path-injection/) query.

## Impact

This issue may lead up to Remote Code Execution (RCE).
