# Goroutine Leak in Abacus SSE Implementation

**GHSA**: GHSA-vh64-54px-qgf8 | **CVE**: CVE-2025-27421 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400, CWE-772

**Affected Packages**:
- **github.com/jasonlovesdoggo/abacus** (go): < 0.0.0-20250302043802-898ff1204e11

## Description

## Goroutine Leak in Abacus SSE Implementation

### Summary

A critical goroutine leak vulnerability has been identified in the Abacus server's Server-Sent Events (SSE) implementation. The issue occurs when clients disconnect from the `/stream` endpoint, as the server fails to properly clean up resources and terminate associated goroutines. This leads to resource exhaustion where the server continues running but eventually stops accepting new SSE connections while maintaining high memory usage. The vulnerability specifically involves improper channel cleanup in the event handling mechanism, causing goroutines to remain blocked indefinitely.

### [POC](https://github.com/JasonLovesDoggo/abacus/blob/main/docs/bugs/GHSA-vh64-54px-qgf8/test.py)

### Impact

This vulnerability affects all versions of Abacus prior to v1.4.0. The issue causes:

- Permanent unresponsiveness of the `/stream` endpoint after prolonged use
- Memory growth that stabilizes at a high level but prevents proper functionality
- Selective denial of service affecting only SSE connections while other endpoints remain functional
- Accumulated orphaned goroutines that cannot be garbage collected
- High resource consumption under sustained client connection/disconnection patterns

Systems running Abacus in production with client applications that frequently establish and terminate SSE connections are most vulnerable. The issue becomes particularly apparent in high-traffic environments or during connection stress testing.

### Patches

The vulnerability has been patched in Abacus v1.4.0. The fix includes:

1. Implementing buffered channels to prevent blocking operations during cleanup
2. Adding proper mutex-protected cleanup logic to ensure resources are released exactly once
3. Implementing timeout protection for channel operations to prevent deadlocks
4. Ensuring consistent cleanup when connections terminate unexpectedly
5. Adding improved monitoring for client disconnections using request context
6. Restructuring the event broadcasting system to safely handle client removal

Users should upgrade to v1.4.0 or later versions as soon as possible.

### Workarounds

If upgrading is not immediately possible, the following workarounds can help mitigate the issue:

1. **Limit maximum connections**: Configure your reverse proxy to limit the maximum number of concurrent connections to the `/stream` endpoints.

2. **Implement request timeouts**: Configure your infrastructure to terminate long-lived SSE connections after a reasonable period.

3. **Restart regularly**: Schedule regular restarts of the Abacus service to reclaim resources.

4. **Monitor memory usage**: Set up alerts for abnormal memory growth patterns.

5. **Separate instance for SSE**: Run a dedicated Abacus instance solely for handling SSE connections, allowing it to be restarted without affecting the main API functionality.

### References

- [Go Concurrency Patterns: Context](https://blog.golang.org/context)
- [CWE-772: Missing Release of Resource after Effective Lifetime](https://cwe.mitre.org/data/definitions/772.html)
- [OWASP Top 10: Resource Exhaustion](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control)
- [Resource Management in Go](https://go.dev/blog/defer-panic-and-recover)

### For More Information

Please contact the Abacus security team at abacus@jsn.cam for additional information or to report further security issues.
