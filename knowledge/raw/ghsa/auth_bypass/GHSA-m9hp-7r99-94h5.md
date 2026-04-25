# Critical security issues in XML encoding in github.com/dexidp/dex

**GHSA**: GHSA-m9hp-7r99-94h5 | **CVE**: CVE-2020-26290 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-347

**Affected Packages**:
- **github.com/dexidp/dex** (go): < 2.27.0
- **github.com/russellhaering/goxmldsig** (go): < 1.1.0

## Description

### Impact

The following vulnerabilities have been disclosed, which impact users leveraging the SAML connector:

Signature Validation Bypass (CVE-2020-15216): https://github.com/russellhaering/goxmldsig/security/advisories/GHSA-q547-gmf8-8jr7

`encoding/xml` instabilities:
 - [Element namespace prefix instability (CVE-2020-29511)](https://github.com/mattermost/xml-roundtrip-validator/blob/master/advisories/unstable-elements.md)
 - [Attribute namespace prefix instability (CVE-2020-29509)](https://github.com/mattermost/xml-roundtrip-validator/blob/master/advisories/unstable-attributes.md)
 - [Directive comment instability (CVE-2020-29510)](https://github.com/mattermost/xml-roundtrip-validator/blob/master/advisories/unstable-directives.md)

### Patches

Immediately update to [Dex v2.27.0](https://github.com/dexidp/dex/releases/tag/v2.27.0).

### Workarounds

There are no known workarounds.
