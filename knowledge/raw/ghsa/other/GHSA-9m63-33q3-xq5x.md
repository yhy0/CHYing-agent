# Vela Server Has Insufficient Webhook Payload Data Verification

**GHSA**: GHSA-9m63-33q3-xq5x | **CVE**: CVE-2025-27616 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-290, CWE-345

**Affected Packages**:
- **github.com/go-vela/server** (go): < 0.25.3
- **github.com/go-vela/server** (go): >= 0.26.0, <= 0.26.2

## Description

### Impact
Users with an enabled repository with access to repo level CI secrets in Vela are vulnerable to the exploit. 

Any user with access to the CI instance and the linked source control manager can perform the exploit.

### Method
By spoofing a webhook payload with a specific set of headers and body data, an attacker could transfer ownership of a repository and its repo level secrets to a separate repository. 

These secrets could be exfiltrated by follow up builds to the repository.

### Patches
`v0.26.3` — Image: `target/vela-server:v0.26.3`
`v0.25.3` — Image: `target/vela-server:v0.25.3`

### Workarounds
_Is there a way for users to fix or remediate the vulnerability without upgrading?_

There are no workarounds to the issue.

### References
_Are there any links users can visit to find out more?_

Please see linked CWEs (common weakness enumerators) for more information.
