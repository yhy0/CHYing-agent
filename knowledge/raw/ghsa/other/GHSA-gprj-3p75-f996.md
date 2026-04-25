# Globus `identity_provider` restriction ignored when used with `allow_all` in JupyterHub 5.0

**GHSA**: GHSA-gprj-3p75-f996 | **CVE**: CVE-2024-37300 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-863

**Affected Packages**:
- **oauthenticator** (pip): < 16.3.1

## Description

### Impact

JupyterHub < 5.0, when used with `GlobusOAuthenticator`, could be configured to allow all users from a particular institution only. The configuration for this would look like:

```python
# Require users to be using the "foo.horse" identity provider, often an institution or university
c.GlobusAuthenticator.identity_provider = "foo.horse"
# Allow everyone who has that identity provider to log in
c.GlobusAuthenticator.allow_all = True
```

This worked fine prior to JupyterHub 5.0, because `allow_all` *did not* take precedence over `identity_provider`.

Since JupyterHub 5.0, `allow_all` *does* take precedence over `identity_provider`. On a hub with the same config, now **all** users will be allowed to login, regardless of `identity_provider`. `identity_provider` will basically be ignored.

This is a [documented change](https://jupyterhub.readthedocs.io/en/stable/howto/upgrading-v5.html#authenticator-allow-all-and-allow-existing-users) in JupyterHub 5.0,
but is likely to catch many users by surprise.

### Patches

OAuthenticator 16.3.1 fixes the issue with JupyterHub 5.0, and does not affect previous versions.

### Workarounds

Do not upgrade to JupyterHub 5.0 when using `GlobusOAuthenticator` in the prior configuration.
