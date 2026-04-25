# IRRd: web UI host header injection allows password reset poisoning via attacker-controlled email links

**GHSA**: GHSA-22m3-c7vp-49fj | **CVE**: CVE-2026-28681 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-601, CWE-640

**Affected Packages**:
- **irrd** (pip): >= 4.4.0, < 4.4.5
- **irrd** (pip): >= 4.5.0, < 4.5.1

## Description

## Impact

An attacker can manipulate the HTTP `Host` header on a password reset or account creation request. The confirmation link in the resulting email can then point to an attacker-controlled domain. Opening the link in the email is sufficient to pass the token to the attacker, who can then use it on the real IRRD instance to take over the account. A compromised account can then be used to modify RPSL objects maintained by the account's mntners and perform other account actions.

If the user had two-factor authentication configured, which is required for users with override access, an attacker is not able to log in, even after successfully resetting the password.

This issue affects IRRD 4.5.0 and all 4.4.x versions prior to 4.4.5. IRRD 4.3 and earlier are not affected, as they did not include the web UI.

## Cause

Email links in account creation, password reset, and mntner migration emails were generated from the HTTP request context, allowing an attacker to manipulate the HTTP `Host` header to redirect these links to an attacker-controlled domain (password reset poisoning).

## Resolution

Requests with a `Host` header that does not match `server.http.url` are now rejected, preventing Host header injection attacks against the web UI.

All existing password reset tokens are invalidated by this upgrade, rendering any tokens that may have been captured by an attacker unusable.

Patched versions: 4.4.5 and 4.5.1.

## Workarounds

Configuring a reverse proxy (such as nginx) to reject requests where the `Host` header does not match the expected hostname is an effective workaround. Enabling two-factor authentication is strongly recommended for all users, as it prevents account takeover even if a password reset token is compromised.

## Detecting exploitation

Because the victim never interacts with the real IRRD instance in this attack, it is difficult to detect exploitation from logs alone.

Indicators that an account was targeted or compromised:

- A `password reset email requested` followed by `password (re)set successfully` where the delay is longer than expected. Legitimate users actively waiting for a reset email tend to complete it quickly; victims who receive an unexpected email are less likely to click it immediately, resulting in a longer delay.
- Users receiving a password reset mail without requesting one.
- If a successfully attacked user later attempts to log in with their original password, this appears in the logs as `user failed login due to invalid account or password`.

After upgrading to a patched release, all existing password reset tokens are invalidated. Users who can still log in with their password after the upgrade can be certain their account has not been taken over.
