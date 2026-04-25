# Dagu affected by unauthenticated RCE via inline DAG spec in default configuration

**GHSA**: GHSA-6qr9-g2xw-cw92 | **CVE**: N/A | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-306

**Affected Packages**:
- **github.com/dagu-org/dagu** (go): <= 1.30.3

## Description

### Summary
Dagu's default configuration ships with authentication disabled. The `POST /api/v2/dag-runs` endpoint accepts an inline YAML spec and executes its shell commands immediately with no credentials required — any dagu instance reachable over the network is fully compromised by default.

### Details
`internal/service/app/config/loader.go:226` sets `AuthModeNone` as the default. With no auth mode configured, `internal/frontend/api/v2/handlers/api.go:520` returns `nil` from `requireExecute()` — all permission checks pass without a valid session.

The `POST /api/v2/dag-runs` endpoint accepts a `spec` field containing a full YAML DAG definition. The spec is parsed and the commands execute immediately on the host with no validation beyond YAML parsing.

### PoC
```bash
curl -s -X POST http://TARGET:8080/api/v2/dag-runs \
  -H "Content-Type: application/json" \
  -d '{"name":"poc","spec":"steps:\n  - name: rce\n    command: id > /tmp/pwned\n"}'
# Response: {"dagRunId":"<uuid>"}
# /tmp/pwned contains: uid=1000(dagu) gid=1000(dagu)
```
Confirmed on `ghcr.io/dagu-org/dagu:latest` with no configuration changes.

### Impact
Every dagu deployment using default settings — every Docker deployment, every install following the documentation, every instance without explicit `DAGU_AUTH_MODE` configuration — is fully compromised without credentials. An attacker with network access gets OS command execution as the dagu process user.
