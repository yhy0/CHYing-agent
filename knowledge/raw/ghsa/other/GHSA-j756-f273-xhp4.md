# github.com/nats-io/nats-server Import token permissions checking not enforced

**GHSA**: GHSA-j756-f273-xhp4 | **CVE**: N/A | **Severity**: high (CVSS 7.5)

**CWE**: CWE-755, CWE-863

**Affected Packages**:
- **github.com/nats-io/nats-server/v2** (go): < 2.2.0

## Description

(This advisory is canonically <https://advisories.nats.io/CVE/CVE-2021-3127.txt>)

## Problem Description

The NATS server provides for Subjects which are namespaced by Account; all Subjects are supposed to be private to an account, with an Export/Import system used to grant cross-account access to some Subjects.  Some Exports are public, such that anyone can import the relevant subjects, and some Exports are private, such that the Import requires a token JWT to prove permission.

The JWT library's validation of the bindings in the Import Token incorrectly warned on mismatches, instead of outright rejecting the token.

As a result, any account can take an Import token used by any other account and re-use it for themselves because the binding to the importing account is not rejected, and use it to import *any* Subject from the Exporting account, not just the Subject referenced in the Import Token.

The NATS account-server system treats account JWTs as semi-public information, such that an attacker can easily enumerate all account JWTs and retrieve all Import Tokens from those account JWTs.

The CVE identifier should cover the JWT library repair and the nats-server containing the fixed JWT library, and any other application depending upon the fixed JWT library.


## Affected versions

#### JWT library

 * all versions prior to 2.0.1
 * fixed after nats-io/jwt#149 landed (2021-03-14)

#### NATS Server

 * Version 2 prior to 2.2.0
   + 2.0.0 through and including 2.1.9 are vulnerable
 * fixed with nats-io/nats-server@423b79440c (2021-03-14)


## Impact

In deployments with untrusted accounts able to update the Account Server with imports, a malicious account can access any Subject from an account which provides Exported Subjects.

Abuse of this facility requires the malicious actor to upload their tampered Account JWT to the Account Server, providing the service operator with a data-store which can be scanned for signs of abuse.


## Workaround

Deny access to clients to update their account JWT in the account server.


## Solution

Upgrade the JWT dependency in any application using it.

Upgrade the NATS server if using NATS Accounts (with private Exports; Account owners can create those at any time though).

Audit all accounts JWTs to scan for exploit attempts; a Python script to audit the accounts can be found at <https://gist.github.com/philpennock/09d49524ad98043ff11d8a40c2bb0d5a>.
