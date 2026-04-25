# Norman API Cross-site Scripting Vulnerability

**GHSA**: GHSA-r8f4-hv23-6qp6 | **CVE**: CVE-2023-32193 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-80

**Affected Packages**:
- **github.com/rancher/norman** (go): < 0.0.0-20240207153100-3bb70b772b52

## Description

### Impact
A vulnerability has been identified in which unauthenticated cross-site scripting (XSS) in Norman's public API endpoint can be exploited. This can lead to an attacker exploiting the vulnerability to trigger JavaScript code and execute commands remotely. 

The attack vector was identified as a Reflected XSS.

Norman API propagates malicious payloads from user input to the UI, which renders the output. For example, a malicious URL gets rendered into a script that is executed on a page.

The changes addressed by this fix are:
- Encode input that comes from the request URL before adding it to the response.
- The request input is escaped by changing the URL construction that is used for links to use `url.URL`.
- The request input is escaped by escaping the JavaScript and CSS variables with attribute encoding as defined by [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#output-encoding-rules-summary).

### Patches
Patched versions include the following commits:

| Branch    | Commit |
| -------- | ------- |
| master  | 3bb70b7 |
| release/v2.8 | a6a6cf5 |
| release/v2.7 | cb54924 |
| release/v2.7.s3 | 7b2b467 |
| release/v2.6 | bd13c65 |

### Workarounds
There is no direct mitigation besides updating Norman API to a patched version.

### References
If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security-related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).

