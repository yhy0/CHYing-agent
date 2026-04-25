# Caddy-SSH vulnerable to Authorization Bypass due to incorrect usage of PAM library

**GHSA**: GHSA-gmhj-xjfh-cf6m | **CVE**: N/A | **Severity**: high (CVSS 7.7)

**CWE**: CWE-287

**Affected Packages**:
- **github.com/mohammed90/caddy-ssh** (go): = 0.0.1

## Description

Not invoking a call to `pam_acct_mgmt` after a call to `pam_authenticate` to check the validity of a login can lead to an authorization bypass.

### Impact

#### Exploitability

The attack can be carried over the network. A complex non-standard configuration or a specialized condition is required for the attack to be successfully conducted. The attacker also requires access to a users credentials, be it expired, for an attack to be successful. There is no user interaction required for successful execution. The attack can affect components outside the scope of the target module.

#### Impact

Using this attack vector, an attacker may access otherwise restricted parts of the system. The attack can be used to gain access to confidential files like passwords, login credentials and other secrets. Hence, it has a high impact on confidentiality. It may also be directly used to affect a change on a system resource. Hence has a medium to high impact on integrity. This attack may not be used to affect the availability of the system. Taking this account an appropriate CVSS v3.1 vector would be
[AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L&version=3.1)

### Root Cause Analysis

In this case, in the following PAM transaction, only a call to `pam.Authenticate` is used to login a user.

https://github.com/mohammed90/caddy-ssh/blob/1d980ceea6e67765daf19b5e644c7a0773fdaa13/internal/authentication/os/pam.go#L60

This implies that a user with expired credentials can still login.

The bug can be verified easily by creating a new user account, expiring it with `chage -E0 <username>` and then trying to log in with the expired credentials.

### Patches
This can be fixed by invoking a call to `pam.AcctMgmt` after a successful call to `pam.Authenticate`

### References
* [Man Page for pam_acct_mgmt](https://man7.org/linux/man-pages/man3/pam_acct_mgmt.3.html)
* [CWE-863](http://cwe.mitre.org/data/definitions/863.html)
* [CWE-285](http://cwe.mitre.org/data/definitions/285.html)

