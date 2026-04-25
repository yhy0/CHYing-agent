# Account Takeover via Session Fixation in Zitadel [Bypassing MFA]

**GHSA**: GHSA-mq4x-r2w3-j7mr | **CVE**: CVE-2024-28197 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-269, CWE-384

**Affected Packages**:
- **github.com/zitadel/zitadel** (go): < 2.44.3
- **github.com/zitadel/zitadel** (go): >= 2.45.0, < 2.45.1

## Description

### Impact
ZITADEL uses a cookie to identify the user agent (browser) and its user sessions. 

Although the cookie was handled according to best practices, it was accessible on subdomains of the ZITADEL instance. An attacker could take advantage of this and provide a malicious link hosted on the subdomain to the user to gain access to the victim’s account in certain scenarios. 
A possible victim would need to login through the malicious link for this exploit to work. 

If the possible victim already had the cookie present, the attack would not succeed. The attack would further only be possible if there was an initial vulnerability on the subdomain. This could either be the attacker being able to control DNS or a XSS vulnerability in an application hosted on a subdomain.

### Patches
2.x versions are fixed on >= [2.46.0](https://github.com/zitadel/zitadel/releases/tag/v2.46.0)
2.45.x versions are fixed on >= [2.45.1](https://github.com/zitadel/zitadel/releases/tag/v2.45.1)
2.44.x versions are fixed on >= [2.44.3](https://github.com/zitadel/zitadel/releases/tag/v2.44.3)

ZITADEL recommends upgrading to the latest versions available in due course.

Note that applying the patch will invalidate the current cookie and thus users will need to start a new session and existing sessions (user selection) will be empty.

### Workarounds
For self-hosted environments unable to upgrade to a patched version, prevent setting the following cookie name on subdomains of your ZITADEL instance (e.g. within your WAF): `__Secure-zitadel-useragent`

### References
None

### Questions
If you have any questions or comments about this advisory, please email us at [security@zitadel.com](mailto:security@zitadel.com)

### Credits
Thanks to Amit Laish – GE Vernova for finding and reporting the vulnerability.
