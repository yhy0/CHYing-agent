# Rancher does not automatically clean up a user deleted or disabled from the configured Authentication Provider

**GHSA**: GHSA-9ghh-mmcq-8phc | **CVE**: CVE-2023-22650 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-287, CWE-306, CWE-613

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.7.0, < 2.7.14
- **github.com/rancher/rancher** (go): >= 2.8.0, < 2.8.5

## Description

### Impact

A vulnerability has been identified in which Rancher does not automatically clean up a user which has been deleted from the configured authentication provider (AP). This characteristic also applies to disabled or revoked users, Rancher will not reflect these modifications which may leave the user’s tokens still usable.

An AP must be enabled to be affected by this, as the built-in User Management feature is not affected by this vulnerability.
This issue may lead to an adversary gaining unauthorized access, as the user’s access privileges may still be active within Rancher even though they are no longer valid on the configured AP (please consult the [MITRE ATT&CK - Technique - Valid Accounts](https://attack.mitre.org/techniques/T1078/) for further information about the associated technique of attack).

It’s important to note that all configurable APs are impacted, see [Rancher Docs - Configuring Authentication - External vs. Local Authentication](https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/authentication-permissions-and-global-configuration/authentication-config#external-vs-local-authentication) to get the full authentication providers list.


To address this issue, the fix introduces a new user retention process that can be configured to run periodically and disable and/or delete inactive users. If enabled a user becomes subject to retention if they don't login for a configurable period of time. It's possible to set overrides for users that are used mainly for programmatic access (e.g. CI, scripts etc.) so that they don't become subject to retention for a longer period of time or at all. The user retention process is disabled by default, to avoid deleting wrong accounts. It is up to each user to enable it and configure the retention period as it best suits its environment.

Be aware that once the process is enabled, it might take a few days for previous users that have been revoked or deleted from the AP to be automatically removed from Rancher. To attenuate the risk of this condition, we recommend to regularly audit the AP’s user accounts for activity and manually deactivate or remove them from Rancher, if they are no longer needed.

For further information about the user retention process configuration, please refer to the dedicated documentation [Rancher Docs - Advanced User Guides - Enable User Retention](https://ranchermanager.docs.rancher.com/how-to-guides/advanced-user-guides/enable-user-retention).

### Patches

Patched versions include releases `2.7.14` and `2.8.5`.

### Workarounds

Administrators that are unable to update to a patched Rancher Manager version, are advised to delete Rancher users, via kubectl or through the UI, as soon as those users are deleted from the Authentication Provider. If a user needs to be temporarily disabled on the Authentication Provider, similar intervention will need to take place to reflect that change on Rancher Manager.


Below is a procedure to list and remove a deleted/disabled user in Rancher using `kubectl` (with a privileged kubeconfig).

1. List all users bound to a supported external auth provider, then returns `username`, `uid`, `displayName` and `PrincipalIds` which contains the related `authprovider_user://ID`

```shell
#!/bin/bash

for authprovider in {activedirectory,azure,common,genericoidc,github googleauth, keycloakoidc,ldap,oidc,publicapi,saml}
do 
	kubectl get users -o json | jq --arg authprovider "$authprovider" '.items[] | select(.principalIds[] | test("^" + $authprovider + "_user://")) | {username: .metadata.name, uid: .metadata.uid, displayName: .displayName, principalIds: .principalIds}'
done
```

2. Once the `authprovider_user://ID` (and/or `DisplayName`) is confirmed, remove the user from the Rancher UI or using `kubectl delete users <USERNAME>`.


### For more information

If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).

