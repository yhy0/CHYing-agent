# Rancher CLI skips TLS verification on Rancher CLI login command

**GHSA**: GHSA-mc24-7m59-4q5p | **CVE**: CVE-2025-67601 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-295

**Affected Packages**:
- **github.com/rancher/rancher** (go): < 0.0.0-20260129092249-bb0625fd1896
- **github.com/rancher/rancher** (go): >= 2.13.0, < 2.13.2
- **github.com/rancher/rancher** (go): >= 2.12.0, < 2.12.6
- **github.com/rancher/rancher** (go): >= 2.11.0, < 2.11.10
- **github.com/rancher/rancher** (go): >= 2.10.0, < 2.10.11

## Description

### Impact
A vulnerability has been identified within Rancher Manager, where using self-signed CA certificates and passing the `-skip-verify` flag to the Rancher CLI login command without also passing the `–cacert` flag results in the CLI attempting to fetch CA certificates stored in Rancher’s setting cacerts. This does not apply to any other commands and only applies to the login command if the `–cacert` flag was not provided.

An attacker with network-level access between the Rancher CLI and Rancher Manager could interfere with the TLS handshake to return a CA they control, despite the use of the `--skip-verify` flag. This may be abused to bypass TLS as a security control. Attackers can also see basic authentication headers in a Man-in-the-Middle due to the lack of TLS enforcement.

Please consult the associated [MITRE ATT&CK - Technique - Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/) for further information about this category of attack.

### Patches
This vulnerability is addressed by removing the ability to fetch CA certificates stored in Rancher’s setting cacerts when using the login command. Whenever required, for example when using self-signed certificates, CA certificates have to be explicitly passed with the –cacert flag.

Patched versions of Rancher include releases `v2.13.2`, `v2.12.6`, `v2.11.10`, and `v2.10.11`.

### Workarounds
If a projecct can't upgrade to a fixed version, please make sure whenever required, for example when using self-signed certificates, to always explicitly pass CA certificates with the –cacert flag when using the login command.


### References
If there are any questions or comments about this advisory:
- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with the [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).

Note: Rancher versions beyond 2.3.0-alpha5 are no longer supported at pkg.go.dev, follow [Rancher installation instructions for newer versions](https://ranchermanager.docs.rancher.com/v2.13/getting-started/installation-and-upgrade).
