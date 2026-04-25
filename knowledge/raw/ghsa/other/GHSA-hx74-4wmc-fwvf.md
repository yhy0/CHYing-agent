# Duplicate Advisory: EVE Has Partially Predetermined Vault Key

**GHSA**: GHSA-hx74-4wmc-fwvf | **CVE**: N/A | **Severity**: high (CVSS 7.9)

**CWE**: CWE-321, CWE-798

**Affected Packages**:
- **github.com/lf-edge/eve** (go): < 0.0.0-20220310190112-c0c966dc31e2

## Description

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-wc42-fcjp-v8vq. This link is maintained to preserve external references.

### Original Description
Due to the implementation of "deriveVaultKey", prior to version 7.10, the generated vault key
would always have the last 16 bytes predetermined to be "arfoobarfoobarfo".

This issue happens because "deriveVaultKey" calls "retrieveCloudKey" (which will always
return "foobarfoobarfoobarfoobarfoobarfo" as the key), and then merges the 32byte
randomly generated key with this key (by takeing 16bytes from each, see "mergeKeys").

This makes the key a lot weaker.

This issue does not persist in devices that were initialized on/after version 7.10, but devices
that were initialized before that and updated to a newer version still have this issue.



Roll an update that enforces the full 32bytes key usage.
