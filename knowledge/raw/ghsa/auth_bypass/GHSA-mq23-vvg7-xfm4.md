# Rancher does not Properly Validate Account Bindings in SAML Authentication Enables User Impersonation on First Login

**GHSA**: GHSA-mq23-vvg7-xfm4 | **CVE**: CVE-2025-23389 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-284, CWE-287

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.8.0, < 2.8.13
- **github.com/rancher/rancher** (go): >= 2.9.0, < 2.9.7
- **github.com/rancher/rancher** (go): >= 2.10.0, < 2.10.3

## Description

### Impact
A vulnerability in Rancher has been discovered, leading to a local user impersonation through SAML Authentication on first login.

The issue occurs when a SAML authentication provider (AP) is configured (e.g. Keycloak). A newly created AP user can impersonate any user on Rancher by manipulating cookie values during their initial login to Rancher. This vulnerability could also be exploited if a Rancher user (present on the AP) is removed, either manually or automatically via the [User Retention feature](https://ranchermanager.docs.rancher.com/how-to-guides/advanced-user-guides/enable-user-retention) with delete-inactive-user-after.

More precisely, Rancher validates only a subset of input from the SAML assertion request; however, it trusts and uses values that are not properly validated. An attacker could then configure the saml_Rancher_UserID cookie and the saml_Rancher_Action cookie so that the user principal from the AP will be added to the user specified by the attacker (from saml_Rancher_UserID). Rancher can then be deceived by setting saml_Rancher_UserID to the admin's user ID and saml_Rancher_Action to testAndEnable, thereby executing the vulnerable code path and leading to privilege escalation.

Note that the vulnerability impacts all SAML APs available in Rancher. However the following Rancher deployments are not affected:
1. Rancher deployments not using SAML-based AP.
2. Rancher deployments using SAML-based AP, where all SAML users are already signed in and linked to a Rancher account.

Please consult the associated  [MITRE ATT&CK - Technique - Access Token Manipulation: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/) for further information about this category of attack.

### Patches
This vulnerability is addressed by adding the UserID claim to a JWT signed token, which is protected against tampering. 

Patched versions include releases `v2.8.13`, `v2.9.7` and `v2.10.3`.

### Workarounds
Rancher deployments that can't upgrade, could temporarily disable the SAML-based AP as a temporary workaround. However, upgrading is recommended.

### References
If you have any questions or comments about this advisory:
- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
