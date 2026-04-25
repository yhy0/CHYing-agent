# Helm Controller denial of service

**GHSA**: GHSA-p2g7-xwvr-rrw3 | **CVE**: CVE-2022-36049 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-400, CWE-770

**Affected Packages**:
- **github.com/fluxcd/helm-controller** (go): >= 0.0.4, < 0.23.0
- **github.com/fluxcd/flux2** (go): >= 0.0.17, < 0.32.0

## Description

Helm controller is tightly integrated with the Helm SDK. [A vulnerability](https://github.com/helm/helm/security/advisories/GHSA-7hfp-qfw3-5jxh) found in the Helm SDK allows for specific data inputs to cause high memory consumption, which in some platforms could cause the controller to panic and stop processing reconciliations.

### Impact
In a shared cluster multi-tenancy environment, a tenant could create a HelmRelease that makes the controller panic, denying all other tenants from their Helm releases being reconciled.

### Credits

The initial crash bug was reported by [oss-fuzz](https://github.com/google/oss-fuzz). The Flux Security team produced the first exploit and worked together with the Helm Security team to ensure that both projects were patched timely.

### For more information

If you have any questions or comments about this advisory:
- Open an issue in any of the affected repositories.
- Contact us at the CNCF Flux Channel.

### References

- https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=48360
- https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=44996
- https://github.com/helm/helm/security/advisories/GHSA-7hfp-qfw3-5jxh

