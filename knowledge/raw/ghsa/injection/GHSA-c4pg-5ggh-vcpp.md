# Duplicate Advisory: Sandbox escape in Artemis Java Test Sandbox

**GHSA**: GHSA-c4pg-5ggh-vcpp | **CVE**: N/A | **Severity**: high (CVSS 8.3)

**CWE**: CWE-94, CWE-284

**Affected Packages**:
- **de.tum.in.ase:artemis-java-test-sandbox** (maven): < 1.11.2

## Description

## Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-98hq-4wmw-98w9. This link is maintained to preserve external references.

## Original Description
Artemis Java Test Sandbox versions before 1.11.2 are vulnerable to a sandbox escape when an attacker loads untrusted libraries using System.load or System.loadLibrary. An attacker can abuse this issue to execute arbitrary Java when a victim executes the supposedly sandboxed code.
