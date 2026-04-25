# Bypassing Brute Force Protection via Application Crash and In-Memory Data Loss

**GHSA**: GHSA-x32m-mvfj-52xv | **CVE**: CVE-2024-21652 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-307

**Affected Packages**:
- **github.com/argoproj/argo-cd/v2** (go): < 2.8.13
- **github.com/argoproj/argo-cd/v2** (go): >= 2.9.0, < 2.9.9
- **github.com/argoproj/argo-cd/v2** (go): >= 2.10.0, < 2.10.4

## Description

### Summary
An attacker can exploit a chain of vulnerabilities, including a Denial of Service (DoS) flaw and in-memory data storage weakness, to effectively bypass the application's brute force login protection. This makes the application susceptible to brute force attacks, compromising the security of all user accounts.

### Details
The issue arises from two main vulnerabilities:

1. The application crashes due to a previously described DoS vulnerability caused by unsafe array modifications in a multi-threaded environment.
2. The application saves the data of failed login attempts in-memory, without persistent storage. When the application crashes and restarts, this data is lost, resetting the brute force protections.

```go
// LoginAttempts is a timestamped counter for failed login attempts

type LoginAttempts struct {  
// Time of the last failed login LastFailed time.Time `json:"lastFailed"` // Number of consecutive login failures FailCount int `json:"failCount"`

}
```

By chaining these vulnerabilities, an attacker can circumvent the limitations placed on the number of login attempts.

### PoC
1. Run the provided PoC script.
2. Observe that the script makes 6 login attempts, one more than the set limit of 5 failed attempts.
3. This is made possible because the script triggers a server restart via the DoS vulnerability after 5 failed attempts, thus resetting the counter for failed login attempts.

### Impact
This is a critical security vulnerability that allows attackers to bypass the brute force login protection mechanism. Not only can they crash the service affecting all users, but they can also make unlimited login attempts, increasing the risk of account compromise.

