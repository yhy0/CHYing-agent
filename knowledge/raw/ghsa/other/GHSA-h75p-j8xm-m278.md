# CoreDNS Loop Detection Denial of Service Vulnerability

**GHSA**: GHSA-h75p-j8xm-m278 | **CVE**: CVE-2026-26018 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-337

**Affected Packages**:
- **github.com/coredns/coredns** (go): < 1.14.2

## Description

## Executive Summary

A Denial of Service vulnerability exists in CoreDNS's loop detection plugin that allows an attacker to crash the DNS server by sending specially crafted DNS queries. The vulnerability stems from the use of a predictable pseudo-random number generator (PRNG) for generating a secret query name, combined with a fatal error handler that terminates the entire process.

---
## Technical Details

### Vulnerability Description

The CoreDNS `loop` plugin is designed to detect forwarding loops by performing a self-test during server startup. The plugin generates a random query name (`qname`) using Go's `math/rand` package and sends an HINFO query to itself. If the server receives multiple matching queries, it assumes a forwarding loop exists and terminates.

**The vulnerability arises from two design flaws:**

1. **Predictable PRNG Seed**: The random number generator is seeded with `time.Now().UnixNano()`, making the generated qname predictable if an attacker knows the approximate server start time.

2. **Fatal Error Handler**: When the plugin detects what it believes is a loop (3+ matching HINFO queries), it calls `log.Fatalf()` which invokes `os.Exit(1)`, immediately terminating the process without cleanup or recovery.

### Affected Code

**File: `plugin/loop/setup.go`**
```go
// PRNG seeded with predictable timestamp
var r = rand.New(time.Now().UnixNano())

// Qname generation using two consecutive PRNG calls
func qname(zone string) string {
    l1 := strconv.Itoa(r.Int())
    l2 := strconv.Itoa(r.Int())
    return dnsutil.Join(l1, l2, zone)
}
```

**File: `plugin/loop/loop.go`**
```go
func (l *Loop) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
    // ... validation checks ...
    
    if state.Name() == l.qname {
        l.inc()  // Increment counter
    }

    if l.seen() > 2 {
        // FATAL: Terminates entire process
        log.Fatalf("Loop (%s -> %s) detected for zone %q...", ...)
    }
    
    // ...
}
```

**File: `plugin/pkg/log/log.go`**
```go
func Fatalf(format string, v ...any) {
    logf(fatal, format, v...)
    os.Exit(1)  // Immediate process termination
}
```

### Exploitation Window

The loop plugin remains active during the following conditions:

| Condition | Window Duration | Attack Feasibility |
|-----------|-----------------|-------------------|
| Healthy startup | 2 seconds | Requires precise timing |
| Self-test failure (upstream unreachable) | 30 seconds | **HIGH** - Extended window |
| Network degradation | Variable | Depends on retry behavior |

### Attack Scenario

**Primary Attack Vector: Network Degradation**

When the upstream DNS server is unreachable (network partition, misconfiguration, outage), the loop plugin's self-test fails repeatedly. During this period:

1. The loop plugin remains active for up to 30 seconds
2. Each self-test attempt generates an HINFO query visible in CoreDNS logs
3. An attacker with log access (shared Kubernetes cluster, centralized logging) can observe the qname
4. The attacker sends 3 HINFO queries with the observed qname
5. The server immediately crashes

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         ATTACK TIMELINE                                  │
├──────────────────────────────────────────────────────────────────────────┤
│ T+0s     CoreDNS starts, PRNG seeded with UnixNano()                     │
│ T+0.5s   Self-test HINFO query sent (visible in logs)                    │
│ T+2s     Self-test fails (upstream timeout)                              │
│ T+3s     Retry #1 - counter resets, qname unchanged                      │
│ T+5s     Retry #2 - attacker observes qname in logs                      │
│ T+5.1s   ATTACKER: Send HINFO #1 → counter = 1                           │
│ T+5.2s   ATTACKER: Send HINFO #2 → counter = 2                           │
│ T+5.3s   ATTACKER: Send HINFO #3 → counter = 3 → os.Exit(1)              │
│ T+5.3s   SERVER CRASHES                                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Impact Assessment

### Attack Requirements

| Requirement | Notes |
|-------------|-------|
| Network Access | Must be able to send UDP packets to CoreDNS port |
| Log Access | Required to observe the qname (common in shared clusters) |
| Timing | Extended window during network degradation |
| Authentication | None required |

### Real-World Impact

CoreDNS is the default DNS server for Kubernetes clusters. A successful attack would:

1. **Disruption**: All DNS resolution fails within the cluster
2. **Cascading Failures**: Services unable to discover each other
3. **Restart Loop**: If attack persists, CoreDNS enters crash-restart cycle
4. **Data Plane Impact**: Application-level failures across the cluster

## References

- CoreDNS GitHub: https://github.com/coredns/coredns
- Loop Plugin Documentation: https://coredns.io/plugins/loop/
- Go math/rand Documentation: https://pkg.go.dev/math/rand
