# libp2p DoS vulnerability from lack of resource management

**GHSA**: GHSA-j7qp-mfxf-8xjw | **CVE**: CVE-2022-23492 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/libp2p/go-libp2p** (go): < 0.18.0

## Description

### Impact
Versions older than `v0.18.0` of go-libp2p are vulnerable to targeted resource exhaustion attacks. These attacks target libp2p’s connection, stream, peer, and memory management. An attacker can cause the allocation of large amounts of memory, ultimately leading to the process getting killed by the host’s operating system. While a connection manager tasked with keeping the number of connections within manageable limits has been part of go-libp2p, this component was designed to handle the regular churn of peers, not a targeted resource exhaustion attack.

In the original version of the attack, the malicious node would continue opening new streams on a stream multiplexer that doesn’t provide sufficient back pressure (yamux or mplex). It is easy to defend against this one attack, but there are countless variations of this attack:
* Opening streams and causing a non-trivial memory allocation (e.g., for multistream or protobuf parsing)
* Creating a lot of sybil nodes and opening new connections across nodes

### Patches (What to do as a go-libp2p consumer:)
1. Update your go-libp2p dependency to go-libp2p v0.18.0 or greater (current version as of publish date is [v0.24.0](https://github.com/libp2p/go-libp2p/releases/tag/v0.24.0).)
    - Note: **It's recommend that you update to `v0.21.0` onwards** as you’ll get some useful functionality that will help in production environments like better metrics around resource usage, Grafana dashboards around resource usage, allow list support, and default autoscaling limits. [Please see the v0.21.0 release notes for more info.](https://github.com/libp2p/go-libp2p/releases/tag/v0.21.0))

2. Determine appropriate limits for your application - go-libp2p sets up a resource manager with the default limits if none are provided. For default definitions please see [limits_defaults.go](https://github.com/libp2p/go-libp2p/blob/master/p2p/host/resource-manager/limit_defaults.go). These limits are also set to automatically scale, this is done using the [AutoScale method of the ScalingLimitConfig](https://github.com/libp2p/go-libp2p/blob/master/p2p/host/resource-manager/README.md#scaling-limits). We recommend you [tune your limits as described here](https://github.com/libp2p/go-libp2p/blob/master/p2p/host/resource-manager/README.md#how-to-tune-your-limits).

3. Configure your node to be attack resilient. See [how to respond to an attack and identify misbehaving peers here](https://docs.libp2p.io/concepts/security/dos-mitigation/#responding-to-an-attack). Then setup automatic blocking with fail2ban using canonical libp2p log lines: [guide on how to do so here](https://docs.libp2p.io/concepts/security/dos-mitigation/#how-to-automate-blocking-with-fail2ban).

#### Examples
* Lotus’ integration can be found in https://github.com/filecoin-project/lotus/blob/master/node/modules/lp2p/rcmgr.go. Lotus reads user-configured resource limits from a limits.json file into the root directory. This allows users to share their resource manager configuration independent of any other configurations.
* Kubo’s (formerly go-ipfs) integration can be found in https://github.com/ipfs/go-ipfs/blob/master/core/node/libp2p/rcmgr.go. Kubo reads the limits from the IPFS config file.

**Note:** go-libp2p still implements the [connection manager](https://github.com/libp2p/go-libp2p/tree/master/p2p/net/connmgr) mentioned above. The connection manager is a component independent of the resource manager, which aims to keep the number of libp2p connections between a low and a high watermark. When modifying connection limits, it’s advantageous to keep the configuration of these components consistent, i.e., when setting a limit of N concurrent connections in the resource manager, the high watermark should be at most (and ideally slightly less) than N.

### Workarounds
Although there are no workarounds within go-libp2p, some range of attacks can be mitigated using OS tools (like manually blocking malicious peers using `iptables` or `ufw` ) or making use of a load balancer in front of libp2p nodes.

However these require direct action & responsibility on your part and are no substitutes for upgrading go-libp2p. Therefore, we highly recommend upgrading your go-libp2p version for the way it enables tighter scoped limits and provides visibility into and easier reasoning about go-libp2p resource utilization.

### References
Please see our DoS Mitigation page for more information on how to incorporate mitigation strategies, monitor your application, and respond to attacks: https://docs.libp2p.io/reference/dos-mitigation/. 

Please see the related disclosure for rust-libp2p: https://github.com/libp2p/rust-libp2p/security/advisories/GHSA-jvgw-gccv-q5p8 and js-libp2p: https://github.com/libp2p/js-libp2p/security/advisories/GHSA-f44q-634c-jvwv

#### For more information

If you have any questions or comments about this advisory email us at [security@libp2p.io](mailto:security@libp2p.io)
