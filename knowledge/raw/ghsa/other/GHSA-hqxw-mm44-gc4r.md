# Istio Fragments in Path May Lead to Authorization Policy Bypass

**GHSA**: GHSA-hqxw-mm44-gc4r | **CVE**: CVE-2021-39156 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-706, CWE-863

**Affected Packages**:
- **istio.io/istio** (go): < 1.9.8
- **istio.io/istio** (go): >= 1.10.0, < 1.10.4
- **istio.io/istio** (go): = 1.11.0

## Description

### Impact
Istio 1.11.0, 1.10.3 and below, and 1.9.7 and below contain a remotely exploitable vulnerability where an HTTP request with `#fragment` in the path may bypass Istio’s URI path based authorization policies. 

### Patches
* Istio 1.11.1 and above
* Istio 1.10.4 and above
* Istio 1.9.8 and above

### Workarounds
A Lua filter may be written to normalize the path.  This is similar to the Path normalization presented in the [Security Best Practices](https://istio.io/latest/docs/ops/best-practices/security/#case-normalization) guide.

### References
More details can be found in the [Istio Security Bulletin](https://istio.io/latest/news/security/istio-security-2021-008)

### For more information
If you have any questions or comments about this advisory, please email us at istio-security-vulnerability-reports@googlegroups.com

