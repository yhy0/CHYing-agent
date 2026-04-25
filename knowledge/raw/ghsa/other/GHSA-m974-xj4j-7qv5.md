# Boxo bitswap/server: DOS unbounded persistent memory leak

**GHSA**: GHSA-m974-xj4j-7qv5 | **CVE**: CVE-2023-25568 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-400, CWE-770

**Affected Packages**:
- **github.com/ipfs/go-libipfs** (go): >= 0.5.0, < 0.6.0
- **github.com/ipfs/go-libipfs** (go): < 0.4.1

## Description

### Impact
An attacker is able allocate arbitrarily many bytes in the Bitswap server by sending many `WANT_BLOCK` and or `WANT_HAVE` requests which are queued in an unbounded queue, with allocations that persist even if the connection is closed.
This affects users accepting untrusted connections with the Bitswap server, this also affects users using the old API stubs at `github.com/ipfs/boxo/bitswap` because it transitively uses `github.com/ipfs/boxo/bitswap/server`.

We have [renamed go-libipfs to boxo](https://github.com/ipfs/boxo/issues/215); this document uses both terms interchangeably. The version numbers for both are applicable, as they share the same historical timeline.

### Remediation
Apply one of:
- Update `boxo` to [`v0.6.0`](https://github.com/ipfs/boxo/releases/tag/v0.6.0) or later
- Update `boxo` to [`v0.4.1`](https://github.com/ipfs/boxo/releases/tag/v0.4.1)
   Note that ***`v0.5.0` is NOT safe***, `v0.4.1` is a backport of the `v0.6.0` security fixes on top of `v0.4.0`.

### Mitigations
1. The server now limits how many wantlist entries per peer it knows.
    The `MaxQueuedWantlistEntriesPerPeer` option allows configuring how many wantlist entries the server remembers; if a peer sends a wantlist bigger than this (including a sum of multiple delta updates) the server will truncate the wantlist to the match the limit.
    This defaults to `1024` entries per peer.
2. The server now properly clears state about peers when they disconnect.
    Peer state is more lazily allocated (only when a wantlist is received in the first place) and is properly cleared when the `PeerDisconnected` callback is received.
3. The server now ignores CIDs above some size.
    Clients were able to send any CID as long as the total protobuf message were bellow the 4MiB limit. This is allowed to allocate lots of memory with very little entries.
    This can be configured using the `MaxCidSize` option and defaults to `168 bytes`.
4. The server now closes the connection if an inline CID is requested (either as `WANT_*` or `CANCEL`).
    The attack were more effective if done with CIDs that are present in target's blockstore, this is because this will push longer-lasting jobs on some priority queue.
    Since inline CID are literal data (instead of hashes of data), everyone always "has" any inline CID (since instead of loading the data from disk, it can be extracted from the CID). It makes no sense for anyone to ever ask you about an inline CID since they could also just parse it themselves. Thus, as a defensive measure, we kill the connection with peers that ask about an inline CID.

### Vulnerable symbols
- `github.com/ipfs/go-libipfs/bitswap/server/internal/decision.(*Engine).MessageReceived`
- `github.com/ipfs/go-libipfs/bitswap/server/internal/decision.(*Engine).NotifyNewBlocks`
- `github.com/ipfs/go-libipfs/bitswap/server/internal/decision.(*Engine).findOrCreate`
- `github.com/ipfs/go-libipfs/bitswap/server/internal/decision.(*Engine).PeerConnected`

### Patches
- https://github.com/ipfs/boxo/commit/9cb5cb54d40b57084d1221ba83b9e6bb3fcc3197 (mitigations 1 and 2)
- https://github.com/ipfs/boxo/commit/62cbac40b96f49e39cd7fedc77ee6b56adce4916 (mitigations 3 and 4)
- https://github.com/ipfs/boxo/commit/baa748b682fabb21a4c1f7628a8af348d4645974 (tests)

### Workarounds
If you are using the stubs at `github.com/ipfs/go-libipfs/bitswap` and not taking advantage of the features provided by the server, refactoring your code to use the new split API will allow you to run in a client-only mode using: [`github.com/ipfs/boxo/bitswap/client`](https://pkg.go.dev/github.com/ipfs/boxo/bitswap/client).
