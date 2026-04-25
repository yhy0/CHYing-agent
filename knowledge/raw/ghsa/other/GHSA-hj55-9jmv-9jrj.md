# Duplicate Advisory: Sandbox escape in Artemis Java Test Sandbox

**GHSA**: GHSA-hj55-9jmv-9jrj | **CVE**: N/A | **Severity**: high (CVSS 8.3)

**CWE**: CWE-501

**Affected Packages**:
- **de.tum.in.ase:artemis-java-test-sandbox** (maven): < 1.8.0

## Description

## Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-227w-wv4j-67h4. This link is maintained to preserve external references.

## Original Description
Artemis Java Test Sandbox versions before 1.8.0 are vulnerable to a sandbox escape when an attacker includes class files in a package that Ares trusts. An attacker can abuse this issue to execute arbitrary Java when a victim executes the supposedly sandboxed code.
