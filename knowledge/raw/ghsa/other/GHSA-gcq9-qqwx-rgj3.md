# libp2p nodes vulnerable to OOM attack

**GHSA**: GHSA-gcq9-qqwx-rgj3 | **CVE**: CVE-2023-40583 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/libp2p/go-libp2p** (go): <= 0.27.3

## Description

### Summary
In go-libp2p, by using signed peer records a malicious actor can store an arbitrary amount of data in a remote node’s memory. This memory does not get garbage collected and so the victim can run out of memory and crash.

It is feasible to do this at scale. An attacker would have to transfer ~1/2 as much memory it wants to occupy (2x amplification factor).

The attacker can perform this attack over time as the target node’s memory will not be garbage collected.

This can occur because when a signed peer record is received, only the signature validity check is performed but the sender signature is not checked. Signed peer records from randomly generated peers can be sent by a malicious actor. A target node will accept the peer record as long as the signature is valid, and then stored in the peer store.

There is cleanup logic in the peer store that cleans up data when a peer disconnects, but this cleanup is never triggered for the fake peer (from which signed peer records were accepted) because it was never “connected”.

### Impact
If users of go-libp2p in production are not monitoring memory consumption over time, it could be a silent attack i.e. the attacker could bring down nodes over a period of time (how long depends on the node resources i.e. a go-libp2p node on a virtual server with 4 gb of memory takes about 90 sec to bring down; on a larger server, it might take a bit longer.)

### Patches
Update your go-libp2p dependency to the latest release, v0.30.0 at the time of writing.

If you'd like to stay on the 0.27.x release, we strongly recommend users to update to go-libp2p [0.27.7](https://github.com/libp2p/go-libp2p/releases/tag/v0.27.7). Though this OOM issue was fixed in 0.27.4, there were subsequent patch releases afterwards (important fixes for other issues unrelated to the OOM).

### Workarounds
None
