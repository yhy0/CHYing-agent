# Denial of Service (DoS) Vulnerability Due to Unsafe Array Modification in Multi-threaded Environment

**GHSA**: GHSA-6v85-wr92-q4p7 | **CVE**: CVE-2024-21661 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-787

**Affected Packages**:
- **github.com/argoproj/argo-cd** (go): <= 1.8.7
- **github.com/argoproj/argo-cd/v2** (go): < 2.8.13
- **github.com/argoproj/argo-cd/v2** (go): >= 2.9.0, < 2.9.9
- **github.com/argoproj/argo-cd/v2** (go): >= 2.10.0, < 2.10.4

## Description

### Summary
An attacker can exploit a critical flaw in the application to initiate a Denial of Service (DoS) attack, rendering the application inoperable and affecting all users. The issue arises from unsafe manipulation of an array in a multi-threaded environment.

### Details
The vulnerability is rooted in the application's code, where an array is being modified while it is being iterated over. This is a classic programming error but becomes critically unsafe when executed in a multi-threaded environment. When two threads interact with the same array simultaneously, the application crashes.

The core issue is located in [expireOldFailedAttempts](https://github.com/argoproj/argo-cd/blob/54601c8fd30b86a4c4b7eb449956264372c8bde0/util/session/sessionmanager.go#L302-L311) function:
```go
func expireOldFailedAttempts(maxAge time.Duration, failures *map[string]LoginAttempts) int {

expiredCount := 0  
for key, attempt := range *failures {

if time.Since(attempt.LastFailed) > maxAge*time.Second { expiredCount += 1  
delete(*failures, key) // Vulnerable code

} }

return expiredCount }
```

The function modifies the array while iterating it which means the code will cause an error and crash the application pod, inspecting the logs just before the crash we can confirm:
```go
goroutine 2032 [running]: github.com/argoproj/argo-cd/v2/util/session.expireOldFailedAttempts(0x12c, 0xc000adecd8)

/go/src/github.com/argoproj/argo-cd/util/session/sessionmanager.go:304 +0x7c github.com/argoproj/argo-cd/v2/util/session.(*SessionManager).updateFailureCount(0xc00035 af50, {0xc001b1f578, 0x11}, 0x1)

/go/src/github.com/argoproj/argo-cd/util/session/sessionmanager.go:320 +0x7f github.com/argoproj/argo-cd/v2/util/session.(*SessionManager).VerifyUsernamePassword(0xc 00035af50, {0xc001b1f578, 0x11}, {0xc000455148, 0x8})
```
### PoC
To reproduce the vulnerability, you can use the following steps:

1. Launch the application.
2. Trigger the code path that results in the `expireOldFailedAttempts()` function being called in multiple threads.
3. In the attached PoC script we are restarting the server in a while loop, causing the application to be unresponsive at all.

### Impact
This is a Denial of Service (DoS) vulnerability. Any attacker can crash the application continuously, making it impossible for legitimate users to access the service. The issue is exacerbated because it does not require authentication, widening the pool of potential attackers.
