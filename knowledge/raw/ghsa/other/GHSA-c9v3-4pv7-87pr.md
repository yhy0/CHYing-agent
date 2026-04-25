# CoreDNS ACL Bypass

**GHSA**: GHSA-c9v3-4pv7-87pr | **CVE**: CVE-2026-26017 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-367

**Affected Packages**:
- **github.com/coredns/coredns** (go): < 1.14.2

## Description

A logical vulnerability in CoreDNS allows DNS access controls to be bypassed due to the default execution order of plugins. Security plugins such as acl are evaluated before the rewrite plugin, resulting in a Time-of-Check Time-of-Use (TOCTOU) flaw.


### Impact

In multi-tenant Kubernetes clusters, this flaw undermines DNS-based segmentation strategies.

Example scenario:
1. ACL blocks access to *.admin.svc.cluster.local
2. A rewrite rule maps public-name → admin.svc.cluster.local
3. An unprivileged pod queries public-name
4. ACL allows the request
5. Rewrite exposes the internal admin service IP

This allows unauthorized service discovery and reconnaissance of restricted internal infrastructure.

### Patches
_Has the problem been patched? What versions should users upgrade to?_

### Workarounds

- Reorder the default plugin.cfg so that:
   - rewrite and other normalization plugins run before acl, opa, and firewall
- Ensure all access control checks are applied after name normalization.
