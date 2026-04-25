# EnvoyProxy Envoy Missing HTTP URL path normalization

**GHSA**: GHSA-2wmf-p7f8-w42h | **CVE**: CVE-2019-9901 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-706

**Affected Packages**:
- **github.com/envoyproxy/envoy** (go): <= 1.9.0

## Description

Envoy 1.9.0 and before does not normalize HTTP URL paths. A remote attacker may craft a relative path, e.g., `something/../admin`, to bypass access control, e.g., a block on `/admin`. A backend server could then interpret the non-normalized path and provide an attacker access beyond the scope provided for by the access control policy.
