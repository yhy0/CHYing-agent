# MinIO is Vulnerable to Privilege Escalation via Session Policy Bypass in Service Accounts and STS

**GHSA**: GHSA-jjjj-jwhf-8rgr | **CVE**: CVE-2025-62506 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/minio/minio** (go): < 0.0.0-20251015170045-c1a49490c78e

## Description

### Summary
A privilege escalation vulnerability allows service accounts and STS (Security Token Service) accounts with restricted session policies to bypass their inline policy restrictions when performing "own" account operations, specifically when creating new service accounts for the same user.

### Details
The vulnerability exists in the IAM policy validation logic in `cmd/iam.go`. When validating session policies for restricted accounts performing operations on their own account (such as creating service accounts), the code incorrectly relied on the `DenyOnly` argument.

The `DenyOnly` flag is used to allow accounts to perform actions related to their own account by only checking if the action is explicitly denied. However, when a session policy (sub-policy) is present, the system should validate that the action is actually **allowed** by the session policy, not just that it isn't denied.

### Attack Scenario
  1. An administrator creates a service account or STS account with a restricted inline policy (e.g., access only to bucket1 and bucket2)
  2. The restricted account attempts to create a new service account for itself without specifying any policy restrictions
  3. Due to the bypass, the new service account is created with full parent privileges instead of being restricted by the inline policy
  4. The attacker now has escalated privileges beyond the intended restrictions

### Impact

  **Attack Complexity**: LOW - Exploitation requires only valid credentials for a restricted service/STS account

  **Confidentiality**: HIGH - Attackers can access buckets and objects beyond their intended restrictions

  **Integrity**: HIGH - Attackers can modify, delete, or create objects outside their authorized scope

  **Availability**: NONE - Does not directly impact service availability

### Patches
Fixed in PR https://github.com/minio/minio/pull/21642
Commit: c1a49490c78e9c3ebcad86ba0662319138ace190

Install the release
```
go install -v github.com/minio/minio@RELEASE.2025-10-15T17-29-55Z
```

### Workarounds
No workarounds available. You can upgrade to the latest version immediately.

### Mitigation Steps

1. **Upgrade MinIO**: Update to the latest version containing the fix
2. **Audit Service Accounts**: Review all service accounts created by non-admin accounts
3. **Revoke Suspicious Accounts**: Delete any service accounts that may have been created through exploitation
4. **Review Access Logs**: Check for unauthorized access to sensitive buckets

### Resources

- Fix PR: https://github.com/minio/minio/pull/21642
- Affected code: cmd/iam.go (functions: isAllowedBySessionPolicyForServiceAccount, isAllowedBySessionPolicy)
