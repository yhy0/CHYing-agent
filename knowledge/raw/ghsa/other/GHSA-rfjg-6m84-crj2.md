# Vikunja Vulnerable to Account Takeover via Password Reset Token Reuse

**GHSA**: GHSA-rfjg-6m84-crj2 | **CVE**: CVE-2026-28268 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-459, CWE-640

**Affected Packages**:
- **code.vikunja.io/api** (go): <= 0.24.6

## Description

**Summary**
A critical business logic vulnerability exists in the password reset mechanism of vikunja/api that allows password reset tokens to be reused indefinitely. Due to a failure to invalidate tokens upon use and a critical logic bug in the token cleanup cron job, reset tokens remain valid forever.

This allows an attacker who intercepts a single reset token (via logs, browser history, or phishing) to perform a complete, persistent account takeover at any point in the future, bypassing standard authentication controls.

**Technical Analysis**
The vulnerability stems from two distinct logic errors in the pkg/user/ package that confirm the tokens are never removed.

1. Logic Error in Password Reset (No Invalidation)
In pkg/user/user_password_reset.go, the ResetPassword function successfully updates the user's password but fails to delete the reset token used to authorize the request. Instead, it attempts to delete a TokenEmailConfirm token, leaving the TokenPasswordReset active.

Vulnerable Code: pkg/user/user_password_reset.go (Lines 36-94)
```
func ResetPassword(s *xorm.Session, reset *PasswordReset) (userID int64, err error) {
    // ... [Validation and User Lookup] ...

    // Hash the password
    user.Password, err = HashPassword(reset.NewPassword)
    if err != nil {
        return
    }

    // FLAW: Deletes 'TokenEmailConfirm' instead of the current 'TokenPasswordReset'
    err = removeTokens(s, user, TokenEmailConfirm)
    if err != nil {
        return
    }

    // ... [Update User Status and Return] ...
    // The reset token is never removed and remains valid in the DB.
}
```
2. Logic Error in Token Cleanup (Inverted Expiry)
The background cron job intended to expire old tokens contains an inverted comparison operator. It deletes tokens newer than 24 hours instead of older ones.

Vulnerable Code: pkg/user/token.go (Lines 125-151)
```
func RegisterTokenCleanupCron() {
    // ...
    err := cron.Schedule("0 * * * *", func() {
        // ...
        // FLAW: "created > ?" selects tokens created AFTER 24 hours ago.
        // This deletes NEW valid tokens and keeps OLD expired tokens forever.
        deleted, err := s.
            Where("created > ? AND (kind = ? OR kind = ?)", 
            time.Now().Add(time.Hour*24*-1), 
            TokenPasswordReset, TokenAccountDeletion).
            Delete(&Token{})
        // ...
    })
}

```

**Impact**
Persistent Account Takeover: An attacker with a single valid token can reset the victim's password an unlimited number of times.

Bypass of Remediation: Even if the victim notices suspicious activity and changes their password, the attacker can use the same old token to reset it again immediately.

Infinite Attack Window: Because the cleanup cron is broken, the token effectively has a generic TTL of "forever," allowing exploitation months or years after the token was issued.

**Remediation**
1. Invalidate Token on Use
Update ResetPassword to delete the specific reset token upon successful completion.
`// Recommended Fix
err = removeTokens(s, user, TokenPasswordReset) // Correct TokenKind`
2. Fix Cleanup Logic
Update the SQL query in RegisterTokenCleanupCron to target tokens created before the cutoff time.
`// Recommended Fix
Where("created < ? ...", time.Now().Add(time.Hour*24*-1), ...) // Use Less Than (<)`

A fix is available at https://github.com/go-vikunja/vikunja/releases/tag/v2.1.0
