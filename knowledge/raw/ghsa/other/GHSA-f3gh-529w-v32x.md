# IDOR Vulnerabilities in ZITADEL's Admin API that Primarily Impact LDAP Configurations

**GHSA**: GHSA-f3gh-529w-v32x | **CVE**: CVE-2025-27507 | **Severity**: critical (CVSS 9.0)

**CWE**: CWE-639, CWE-863

**Affected Packages**:
- **github.com/zitadel/zitadel/v2** (go): < 2.63.8
- **github.com/zitadel/zitadel/v2** (go): >= 2.64.0, < 2.64.5
- **github.com/zitadel/zitadel/v2** (go): >= 2.65.0, < 2.65.6
- **github.com/zitadel/zitadel/v2** (go): >= 2.66.0, < 2.66.11
- **github.com/zitadel/zitadel/v2** (go): >= 2.67.0, < 2.67.8
- **github.com/zitadel/zitadel/v2** (go): >= 2.68.0, < 2.68.4
- **github.com/zitadel/zitadel/v2** (go): >= 2.69.0, < 2.69.4
- **github.com/zitadel/zitadel/v2** (go): >= 2.70.0, < 2.70.1
- **github.com/zitadel/zitadel** (go): < 2.63.8
- **github.com/zitadel/zitadel** (go): >= 2.64.0, < 2.64.5
- **github.com/zitadel/zitadel** (go): >= 2.65.0, < 2.65.6
- **github.com/zitadel/zitadel** (go): >= 2.66.0, < 2.66.11
- **github.com/zitadel/zitadel** (go): >= 2.67.0, < 2.67.8
- **github.com/zitadel/zitadel** (go): >= 2.68.0, < 2.68.4
- **github.com/zitadel/zitadel** (go): >= 2.69.0, < 2.69.4
- **github.com/zitadel/zitadel** (go): >= 2.70.0, < 2.70.1

## Description

### Summary

ZITADEL's Admin API contains Insecure Direct Object Reference (IDOR) vulnerabilities that allow authenticated users, without specific IAM roles, to modify sensitive settings. While several endpoints are affected, the most critical vulnerability lies in the ability to manipulate LDAP configurations. Customers who do not utilize LDAP for authentication are not at risk from the most severe aspects of this vulnerability. However, we still strongly recommend upgrading to the patched version to address all identified issues.

### Description

ZITADEL's Admin API, intended for managing ZITADEL instances, contains 12 HTTP endpoints that are unexpectedly accessible to authenticated ZITADEL users who are not ZITADEL managers. The most critical vulnerable endpoints relate to LDAP configuration:

- /idps/ldap
- /idps/ldap/{id}

By accessing these endpoints, unauthorized users could:

- Modify ZITADEL's instance LDAP settings, redirecting all LDAP login attempts to a malicious server, effectively taking over user accounts.  
- Expose the original LDAP server's password, potentially compromising all user accounts.  

### Additional Vulnerable Endpoints

The following endpoints are also affected by IDOR vulnerabilities, potentially allowing unauthorized modification of instance settings such as languages, labels, and templates:

- /idps/templates/_search
- /idps/templates/{id}
- /policies/label/_activate
- /policies/label/logo
- /policies/label/logo_dark
- /policies/label/icon
- /policies/label/icon_dark
- /policies/label/font
- /text/message/passwordless_registration/{language}
- /text/login/{language} 

### Impact

The impact of this vulnerability varies depending on whether a ZITADEL instance utilizes LDAP for authentication:

- LDAP Users: Successful exploitation could lead to complete takeover of user accounts and exposure of the LDAP server's password.  
- Non-LDAP Users: While the most severe risks are related to LDAP, exploitation of the additional vulnerable endpoints could still allow unauthorized modification of instance settings, impacting all organizations. 

### Patches

2.x versions are fixed on >= [2.71.0](https://github.com/zitadel/zitadel/releases/tag/v2.71.0)
2.70.x versions are fixed on >= [2.70.1](https://github.com/zitadel/zitadel/releases/tag/v2.70.1)
2.69.x versions are fixed on >= [2.69.4](https://github.com/zitadel/zitadel/releases/tag/v2.69.4)
2.68.x versions are fixed on >= [2.68.4](https://github.com/zitadel/zitadel/releases/tag/v2.68.4)
2.67.x versions are fixed on >= [2.67.8](https://github.com/zitadel/zitadel/releases/tag/v2.67.8)
2.66.x versions are fixed on >= [2.66.11](https://github.com/zitadel/zitadel/releases/tag/v2.66.11)
2.65.x versions are fixed on >= [2.65.6](https://github.com/zitadel/zitadel/releases/tag/v2.65.6)
2.64.x versions are fixed on >= [2.64.5](https://github.com/zitadel/zitadel/releases/tag/v2.64.5)
2.63.x versions are fixed on >= [2.63.8](https://github.com/zitadel/zitadel/releases/tag/v2.63.8)

### Questions

If you have any questions or comments about this advisory, please email us at security@zitadel.com

### Credit

This vulnerability was discovered by Amit Laish, a senior security researcher from GE Vernova and we want to thank him for reporting this to us!
