# Exposure of server configuration in github.com/go-vela/server

**GHSA**: GHSA-gv2h-gf8m-r68j | **CVE**: CVE-2020-26294 | **Severity**: high (CVSS 7.4)

**CWE**: CWE-78, CWE-200

**Affected Packages**:
- **github.com/go-vela/compiler** (go): < 0.6.1

## Description

### Impact
_What kind of vulnerability is it? Who is impacted?_

* The ability to expose configuration set in the [Vela server](https://github.com/go-vela/server) via [pipeline template functionality](https://go-vela.github.io/docs/templates/overview/).
* It impacts all users of Vela.


Sample of template exposing server configuration [using Sprig's `env` function](http://masterminds.github.io/sprig/os.html):

```yaml
metadata:
  template: true

steps:
  - name: sample
    image: alpine:latest
    commands:
      # OAuth client ID for Vela <-> GitHub communication
      - echo {{ env "VELA_SOURCE_CLIENT" }}
      # secret used for server <-> worker communication
      - echo {{ env "VELA_SECRET" }}
```

### Patches
_Has the problem been patched? What versions should users upgrade to?_

* Upgrade to `0.6.1`

#### Additional Recommended Action(s)

* Rotate all secrets

### Workarounds
_Is there a way for users to fix or remediate the vulnerability without upgrading?_

* No

### For more information

If you have any questions or comments about this advisory:

* Email us at [vela@target.com](mailto:vela@target.com)
