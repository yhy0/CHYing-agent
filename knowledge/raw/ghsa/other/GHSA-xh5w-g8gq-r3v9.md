# Keylime allows users to register new agents by recycling existing UUIDs when using different TPM devices

**GHSA**: GHSA-xh5w-g8gq-r3v9 | **CVE**: CVE-2025-13609 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-694

**Affected Packages**:
- **keylime** (pip): < 7.13.0

## Description

A vulnerability has been identified in keylime where an attacker can exploit this flaw by registering a new agent using a different Trusted Platform Module (TPM) device but claiming an existing agent's unique identifier (UUID). This action overwrites the legitimate agent's identity, enabling the attacker to impersonate the compromised agent and potentially bypass security controls.
