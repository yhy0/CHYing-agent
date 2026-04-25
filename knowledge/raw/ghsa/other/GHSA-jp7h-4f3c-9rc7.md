# OpenBao AWS Plugin Vulnerable to Cross-Account IAM Role Impersonation in AWS Auth Method

**GHSA**: GHSA-jp7h-4f3c-9rc7 | **CVE**: CVE-2025-59048 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-694, CWE-863

**Affected Packages**:
- **github.com/openbao/openbao-plugins** (go): <= 0.1.0

## Description

### Impact
This is a cross-account impersonation vulnerability in the `auth-aws` plugin. The vulnerability allows an IAM role from an untrusted AWS account to authenticate by impersonating a role with the **same name** in a trusted account, leading to unauthorized access.

This impacts all users of the `auth-aws` plugin who operate in a multi-account AWS environment where IAM role names may not be unique across accounts.

The core of the vulnerability is a flawed caching mechanism that fails to validate the AWS Account ID during authentication. While the use of wildcards in a `bound_iam_principal_arn configuration` significantly increases the attack surface, **wildcards are not a prerequisite for exploitation**. The vulnerability can be exploited with specific ARN bindings if a role name collision occurs.

Successful exploitation can lead to unauthorized access to secrets, data exfiltration, and privilege escalation. Given that the only prerequisite is a duplicate role name, the severity is considered **high**.

### Patches
This vulnerability has been patched in version **0.1.1** of the `auth-aws` plugin.
Users are advised to upgrade to version **0.1.1** or later to remediate this vulnerability.

### Workarounds
For users who are unable to upgrade to version **0.1.1** immediately, the most effective workaround is to **guarantee that IAM role names are unique across all AWS accounts** that could potentially interact with your OpenBao environment. This is the most critical mitigation step.

**Primary Mitigation**: Audit your AWS organizations to identify and rename any duplicate IAM role names. Enforce a naming convention that includes account-specific identifiers to prevent future collisions.

While removing wildcards from your `bound_iam_principal_arn` configuration is still recommended as a security best practice, it **will not** mitigate this vulnerability if duplicate role names exist.

### Credits
This vulnerability was discovered and reported by [Pavlos Karakalidis](https://github.com/pkarakal/)
