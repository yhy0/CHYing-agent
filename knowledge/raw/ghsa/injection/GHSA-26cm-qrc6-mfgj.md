# Improper Neutralization of Special Elements used in an LDAP Query in stevenweathers/thunderdome-planning-poker

**GHSA**: GHSA-26cm-qrc6-mfgj | **CVE**: CVE-2021-41232 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-74, CWE-90, CWE-116

**Affected Packages**:
- **github.com/stevenweathers/thunderdome-planning-poker** (go): < 1.16.3

## Description

### Impact
LDAP injection vulnerability, only affects instances with LDAP authentication enabled.

### Patches
Patch for vulnerability released with v1.16.3.

### Workarounds
Disable LDAP feature if in use

### References
[OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
)

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Thunderdome Github Repository](https://github.com/StevenWeathers/thunderdome-planning-poker)
* Email us at [steven@weathers.me](mailto:steven@weathers.me)

