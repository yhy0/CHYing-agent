# Soft Serve Public Key Authentication Bypass Vulnerability when Keyboard-Interactive SSH Authentication is Enabled

**GHSA**: GHSA-mc97-99j4-vm2v | **CVE**: CVE-2023-43809 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/charmbracelet/soft-serve** (go): < 0.6.2

## Description

### Impact

A security vulnerability in Soft Serve could allow an unauthenticated, remote attacker to bypass public key authentication when keyboard-interactive SSH authentication is active, through the `allow-keyless` setting, and the public key requires additional client-side verification for example using FIDO2 or GPG. This is due to insufficient validation procedures of the public key step during SSH request handshake, granting unauthorized access if the keyboard-interaction mode is utilized. An attacker could exploit this vulnerability by presenting manipulated SSH requests using keyboard-interactive authentication mode. This could potentially result in unauthorized access to the Soft Serve.

### Patches

Users should upgrade to the latest Soft Serve version `v0.6.2` to receive the patch for this issue. 

### Workarounds

To workaround this vulnerability without upgrading, users can _temporarily_ disable Keyboard-Interactive SSH Authentication using the `allow-keyless` setting.

### References

https://github.com/charmbracelet/soft-serve/issues/389
