# Duplicate Advisory: Keylime Missing Authentication for Critical Function and Improper Authentication

**GHSA**: GHSA-27jc-jmp8-qfw5 | **CVE**: N/A | **Severity**: critical (CVSS 9.4)

**CWE**: CWE-322

**Affected Packages**:
- **keylime** (pip): >= 7.12.0, < 7.12.2
- **keylime** (pip): = 7.13.0

## Description

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-4jqp-9qjv-57m2. This link is maintained to preserve external references.

### Original Description
A flaw was found in Keylime. The Keylime registrar, since version 7.12.0, does not enforce client-side Transport Layer Security (TLS) authentication. This authentication bypass vulnerability allows unauthenticated clients with network access to perform administrative operations, including listing agents, retrieving public Trusted Platform Module (TPM) data, and deleting agents, by connecting without presenting a client certificate.
