# xkeys seal encryption used fixed key for all encryption

**GHSA**: GHSA-mr45-rx8q-wcm9 | **CVE**: CVE-2023-46129 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-321, CWE-325

**Affected Packages**:
- **github.com/nats-io/nkeys** (go): >= 0.4.0, <= 0.4.5
- **github.com/nats-io/nats-server/v2** (go): >= 2.10.0, <= 2.10.3

## Description

## Background

NATS.io is a high performance open source pub-sub distributed communication technology, built for the cloud, on-premise, IoT, and edge computing.

The cryptographic key handling library, nkeys, recently gained support for encryption, not just for signing/authentication.  This is used in nats-server 2.10 (Sep 2023) and newer for authentication callouts.

## Problem Description

The nkeys library's "xkeys" encryption handling logic mistakenly passed an array by value into an internal function, where the function mutated that buffer to populate the encryption key to use.  As a result, all encryption was actually to an all-zeros key.

This affects encryption only, not signing.  
FIXME: FILL IN IMPACT ON NATS-SERVER AUTH CALLOUT SECURITY.

## Affected versions

nkeys Go library:
 * 0.4.0 up to and including 0.4.5
 * Fixed with nats-io/nkeys: 0.4.6

NATS Server:
 * 2.10.0 up to and including 2.10.3
 * Fixed with nats-io/nats-server: 2.10.4

## Solution

Upgrade the nats-server.  
For any application handling auth callouts in Go, if using the nkeys library, update the dependency, recompile and deploy that in lockstep.

## Credits

Problem reported by Quentin Matillat (GitHub @tinou98).
