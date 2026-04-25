# Rancher update on users can deny the service to the admin

**GHSA**: GHSA-q82v-h4rq-5c86 | **CVE**: CVE-2024-58260 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.12.0, < 2.12.2
- **github.com/rancher/rancher** (go): >= 2.11.0, < 2.11.6
- **github.com/rancher/rancher** (go): >= 2.10.0, < 2.10.10
- **github.com/rancher/rancher** (go): >= 2.9.0, < 2.9.12

## Description

### Impact

A vulnerability has been identified within Rancher Manager where a missing server-side validation on the `.username` field in Rancher can allow users with update permissions on other User resources to cause denial of access for targeted accounts. Specifically:

- Username takeover: A user with permission to update another user’s resource can set its `.username` to "admin", preventing both the legitimate admin and the affected user from logging in, as Rancher enforces uniqueness at login time.
- Account lockout: A user with update permissions on the admin account can change the admin’s username, effectively blocking administrative access to the Rancher UI.

This issue enables a malicious or compromised account with elevated update privileges on User resources to disrupt platform administration and user authentication.

**Note:** The users with these permissions to modify accounts and resources are considered as privileged users. For more information, please consult Rancher Manger’s documentation about [global permissions](https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/authentication-permissions-and-global-configuration/manage-role-based-access-control-rbac/global-permissions).

Please consult the associated  [MITRE ATT&CK - Technique - Account Access Removal](https://attack.mitre.org/techniques/T1531/) for further information about this category of attack.

### Patches

This vulnerability is addressed by adding a new check in the webhook which blocks modifying usernames after it has been set. If it's empty then the username can be set to a username not already in use, but after that it is immutable.

Patched versions of Rancher include releases v2.12.2, v2.11.6, v2.10.10 and v2.9.12.

### Workarounds

If you can't upgrade to a fixed version, please make sure that you are only granting update permissions on users’ related resources to trusted users.

### References

If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
