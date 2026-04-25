# OpenTelemetry Go SDK Vulnerable to Arbitrary Code Execution via PATH Hijacking

**GHSA**: GHSA-9h8m-3fm2-qjrq | **CVE**: CVE-2026-24051 | **Severity**: high (CVSS 7.0)

**CWE**: CWE-426

**Affected Packages**:
- **go.opentelemetry.io/otel/sdk** (go): >= 1.21.0, < 1.40.0

## Description

### Impact
The OpenTelemetry Go SDK in version `v1.20.0`-`1.39.0` is vulnerable to Path Hijacking (Untrusted Search Paths) on macOS/Darwin systems. The resource detection code in `sdk/resource/host_id.go` executes the `ioreg` system command using a search path. An attacker with the ability to locally modify the PATH environment variable can achieve Arbitrary Code Execution (ACE) within the context of the application.

### Patches
This has been patched in [d45961b](https://github.com/open-telemetry/opentelemetry-go/commit/d45961bcda453fcbdb6469c22d6e88a1f9970a53), which was released with `v1.40.0`.

### References
- [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)
