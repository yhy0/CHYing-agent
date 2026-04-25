# Sliver has DNS C2 OTP Bypass that Allows Unauthenticated Session Flooding and Denial of Service

**GHSA**: GHSA-wxrw-gvg8-fqjp | **CVE**: CVE-2026-25791 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-306, CWE-400

**Affected Packages**:
- **github.com/bishopfox/sliver** (go): <= 1.6.11

## Description

## Summary
The DNS C2 listener accepts unauthenticated `TOTP` bootstrap messages and allocates server-side DNS sessions without validating OTP values, even when `EnforceOTP` is enabled. Because sessions are stored without a cleanup/expiry path in this flow, an unauthenticated remote actor can repeatedly create sessions and drive memory exhaustion.

## Vulnerable Component
- `server/c2/dns.go:84-90` (`EnforceOTP` stored but not enforced in bootstrap)
- `server/c2/dns.go:378-390` (`TOTP` requests routed directly to bootstrap)
- `server/c2/dns.go:490-521` (`handleHello` allocates session without OTP validation)
- `server/c2/dns.go:495` (`sessions.Store` with no lifecycle control in this path)
- `client/command/jobs/dns.go:46-52` (operator-facing `EnforceOTP` control implies auth gate)
- `implant/sliver/transports/dnsclient/dnsclient.go:896-900` (`otpMsg` sends `TOTP` with `ID=0`)
- `protobuf/dnspb/dns.proto:22` (documents TOTP in `ID` field)

## Attack Vector
- Network-accessible DNS listener
- No authentication required
- Low-complexity repeated DNS query loop
- Trigger path: `DNSMessageType_TOTP` bootstrap handling

## Proof of Concept
### Preconditions
- DNS listener is reachable
- DNS C2 job is active

### Reproduction Steps
1. Send repeated DNS queries with a minimal protobuf message of type `TOTP`.
2. Observe repeated session allocation/issuance behavior.
3. Continue requests to increase active in-memory session state.

### Example
```bash
while true; do
  dig +short @<DNS_C2_IP> baa8.<parent-domain> A >/dev/null
done
```

`baa8` is a base32 payload for a minimal TOTP-type protobuf message.

### Observable Indicators
- Repeated bootstrap/session-allocation log entries from `handleHello`
- Rising memory usage in the Sliver server process
- Service slowdown or instability under sustained request volume

## Impact
- Unauthenticated remote denial of service (availability)
- Resource exhaustion through unbounded session growth in DNS bootstrap path
- Estimated CVSS v3.1: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (**7.5 High**)
