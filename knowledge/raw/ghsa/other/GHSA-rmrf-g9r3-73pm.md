# flagd Vulnerable to Allocation of Resources Without Limits or Throttling

**GHSA**: GHSA-rmrf-g9r3-73pm | **CVE**: CVE-2026-31866 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/open-feature/flagd/flagd** (go): < 0.14.2

## Description

## Details

flagd exposes OFREP (`/ofrep/v1/evaluate/...`) and gRPC (`evaluation.v1`, `evaluation.v2`) endpoints for feature flag evaluation. These endpoints are designed to be publicly accessible by client applications.

The evaluation context included in request payloads is read into memory without any size restriction. An attacker can send a single HTTP request with an arbitrarily large body, causing flagd to allocate a corresponding amount of memory. This leads to immediate memory exhaustion and process termination (e.g., OOMKill in Kubernetes environments).

flagd does not natively enforce authentication on its evaluation endpoints. While operators may deploy flagd behind an authenticating reverse proxy or similar infrastructure, the endpoints themselves impose no access control by default.

## Impact

- **Denial of Service:** A single crafted request can crash the flagd process.
- **Service Disruption:** All applications relying on the affected flagd instance for feature flag evaluation will lose access to flag evaluations until the process restarts.
- **Repeated Exploitation:** An attacker can continuously send oversized requests to prevent recovery.

## Affected Endpoints

- `/ofrep/v1/evaluate/flags/{flagKey}` (OFREP single flag evaluation)
- `/ofrep/v1/evaluate/flags` (OFREP bulk evaluation)
- `flagd.evaluation.v1.Service/ResolveBoolean` (gRPC/Connect)
- `flagd.evaluation.v1.Service/ResolveString` (gRPC/Connect)
- `flagd.evaluation.v1.Service/ResolveFloat` (gRPC/Connect)
- `flagd.evaluation.v1.Service/ResolveInt` (gRPC/Connect)
- `flagd.evaluation.v1.Service/ResolveObject` (gRPC/Connect)
- `flagd.evaluation.v1.Service/ResolveAll` (gRPC/Connect)
- `flagd.evaluation.v2.Service/ResolveBoolean` (gRPC/Connect)
- `flagd.evaluation.v2.Service/ResolveString` (gRPC/Connect)
- `flagd.evaluation.v2.Service/ResolveFloat` (gRPC/Connect)
- `flagd.evaluation.v2.Service/ResolveInt` (gRPC/Connect)
- `flagd.evaluation.v2.Service/ResolveObject` (gRPC/Connect)
