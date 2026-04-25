# Duplicate Advisory: Sandbox escape in Artemis Java Test Sandbox

**GHSA**: GHSA-23rx-79r7-6cpx | **CVE**: N/A | **Severity**: high (CVSS 8.3)

**CWE**: N/A

**Affected Packages**:
- **de.tum.in.ase:artemis-java-test-sandbox** (maven): < 1.7.6

## Description

## Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-883x-6fch-6wjx. This link is maintained to preserve external references.

## Original Description
Artemis Java Test Sandbox versions less than 1.7.6 are vulnerable to a sandbox escape when an attacker crafts a special subclass of InvocationTargetException. An attacker can abuse this issue to execute arbitrary Java when a victim executes the supposedly sandboxed code.
