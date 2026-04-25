# JWT audience claim is not verified

**GHSA**: GHSA-q9hr-j4rf-8fjc | **CVE**: CVE-2023-22482 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/argoproj/argo-cd** (go): >= 1.8.2, < 2.3.14
- **github.com/argoproj/argo-cd** (go): >= 2.4.0, < 2.4.20
- **github.com/argoproj/argo-cd** (go): >= 2.5.0, < 2.5.8
- **github.com/argoproj/argo-cd** (go): >= 2.6.0-rc1, < 2.6.0-rc5

## Description

### Impact

All versions of Argo CD starting with v1.8.2 are vulnerable to an improper authorization bug causing the API to accept certain invalid tokens.

OIDC providers include an `aud` (audience) claim in signed tokens. The value of that claim specifies the intended audience(s) of the token (i.e. the service or services which are meant to accept the token). Argo CD _does_ validate that the token was signed by Argo CD's configured OIDC provider. But Argo CD _does not_ validate the audience claim, so it will accept tokens that are not intended for Argo CD.

If Argo CD's configured OIDC provider also serves other audiences (for example, a file storage service), then Argo CD will accept a token intended for one of those other audiences. Argo CD will grant the user privileges based on the token's `groups` claim, even though those groups were not intended to be used by Argo CD.

This bug also increases the blast radius of a stolen token. If an attacker steals a valid token for a different audience, they can use it to access Argo CD.

### Patches

A patch for this vulnerability has been released in the following Argo CD versions:

* v2.6.0-rc5
* v2.5.8
* v2.4.20
* v2.3.14

The patch introduces a new `allowedAudiences` to the OIDC config block. By default, the client ID is the only allowed audience. Users who _want_ Argo CD to accept tokens intended for a different audience may use `allowedAudiences` to specify those audiences.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
data:
  oidc.config: |
    name: Example
    allowedAudiences:
    - audience-1
    - audience-2
    - argocd-client-id  # If `allowedAudiences` is non-empty, Argo CD's client ID must be explicitly added if you want to allow it.
``

Even though [the OIDC spec requires the audience claim](https://openid.net/specs/openid-connect-core-1_0.html#IDToken), some tokens may not include it. To avoid a breaking change in a patch release, versions < 2.6.0 of Argo CD will skip the audience claim check for tokens that have no audience. In versions >= 2.6.0, Argo CD will reject all tokens which do not have an audience claim. Users can opt into the old behavior by setting an option:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
data:
  oidc.config: |
    name: Example
    skipAudienceCheckWhenTokenHasNoAudience: true
```

### Workarounds

There is no workaround besides upgrading.

### Credits 

The Argo CD team would like to express their gratitude to Vladimir Pouzanov (@farcaller) from Indeed, who discovered the issue, reported it confidentially according to our [guidelines](https://github.com/argoproj/argo-cd/blob/master/SECURITY.md#reporting-a-vulnerability), and actively worked with the project to provide a remedy. Many thanks to Vladimir!

### References

* [How to configure OIDC in Argo CD](https://argo-cd.readthedocs.io/en/latest/operator-manual/user-management/#existing-oidc-provider)
* [OIDC spec section discussing the audience claim](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
* [JWT spec section discussing the audience claim](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3)

### For more information

* Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
* Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd

