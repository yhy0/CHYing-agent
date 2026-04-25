# Sydent does not verify email server certificates

**GHSA**: GHSA-p6hw-wm59-3g5g | **CVE**: CVE-2023-38686 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-295

**Affected Packages**:
- **matrix-sydent** (pip): < 2.5.6

## Description

## Impact

If configured to send emails using TLS, Sydent does not verify SMTP servers' certificates. This makes  Sydent's emails vulnerable to interception via a [man-in-the-middle (MITM) attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack). Attackers with privileged access to the network can intercept room invitations and address confirmation emails.

CVSS 3.1 overall score: 3.3 - [AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/CR:L/IR:L/AR:X/MAV:A/MAC:H/MPR:N/MUI:N/MS:C/MC:L/MI:L/MA:N](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/CR:L/IR:L/AR:X/MAV:A/MAC:H/MPR:N/MUI:N/MS:C/MC:L/MI:L/MA:N&version=3.1)

_Reported by Martin Schobert, [Pentagrid AG](https://pentagrid.ch/)._

### Details

Sydent can be configured to send emails over a TLS-encrypted socket by setting

```yaml
email:
    tlsmode: "TLS"  # or the legacy value "SSL"
```

in its config file. Alternatively it can be configured to use [Opportunistic TLS](https://en.wikipedia.org/wiki/Opportunistic_TLS) by setting

```yaml
email:
    tlsmode: "STARTTLS"
```

In both situations, Sydent will encrypt its communication with the SMTP server when sending emails. **In affected versions, Sydent will not verify the destination server's certificate.**

### Vulnerability 

Sydent sends email for two purposes:
- to inform a third party that they have been invited to a Matrix room by their email address; and
- to verify that a given Matrix user controls an email address.

Therefore, attackers capable of running a MITM attack can

1. Intercept room invitations sent to an email address. The invitation includes 
   - the room ID and its avatar, and
   - the inviter's username, displayname and their avatar, and
   - credentials for a guest Matrix account on the inviter's homeserver.
2. Intercept address ownership confirmation emails. This would allow the attacker to falsely claim ownership of the indented recipient's Matrix account, if that account was permitted to log in using an email address and no other authentication factors.


### Patches

This is patched in [Sydent 2.5.6](https://github.com/matrix-org/sydent/releases/tag/v2.5.6), see PR https://github.com/matrix-org/sydent/pull/574.

When patching, make sure that Sydent trusts the certificate of the server it is connecting to. This should happen automatically when using properly issued certificates. If you are using self-signed certificates, make sure to copy your Certification Authority certificate, or your self signed certificate if using only one, to the trust store of your operating system.

### Workarounds

One can ensure Sydent's emails fail to send by setting the configured SMTP server to a loopback or [non-routable](https://datatracker.ietf.org/doc/html/rfc1918#section-3) address under your control which does not have a listening SMTP server. For example:

```yaml
email:
    smtphost: "localhost"  # Assuming there is no SMTP server listening on localhost
```

### References

- https://github.com/matrix-org/sydent/pull/574 implements the fix.
- https://github.com/matrix-org/sydent/releases/tag/v2.5.6 is the release including this fix.
- https://docs.python.org/3/library/ssl.html?highlight=ssl#security-considerations details the best-practice advice on how to use the standard library `smtp` module safely.
- https://peps.python.org/pep-0476/ (accepted) proposed enabling TLS certificate verification by default  in standard library HTTP clients.
- https://github.com/python/cpython/issues/91826 discusses enabling TLS certificate verification by default in the Python standard library, for SMTP and other protocols.

## For more information

If you have any questions or comments about this advisory, e-mail us at [security@matrix.org](mailto:security@matrix.org).
