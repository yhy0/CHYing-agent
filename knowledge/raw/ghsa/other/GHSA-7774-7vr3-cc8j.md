# Authorization Policy Bypass Due to Case Insensitive Host Comparison

**GHSA**: GHSA-7774-7vr3-cc8j | **CVE**: CVE-2021-39155 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-178

**Affected Packages**:
- **istio.io/istio** (go): < 1.9.8
- **istio.io/istio** (go): >= 1.10.0, < 1.10.4
- **istio.io/istio** (go): = 1.11.0

## Description

### Impact
According to [RFC 4343](https://datatracker.ietf.org/doc/html/rfc4343), Istio authorization policy should compare the hostname in the HTTP Host header in a case insensitive way, but currently the comparison is case sensitive.  The Envoy proxy will route the request hostname in a case-insensitive way which means the authorization policy could be bypassed.
 
As an example, the user may have an authorization policy that rejects request with hostname "httpbin.foo" for some source IPs, but the attacker can bypass this by sending the request with hostname "Httpbin.Foo".

### Patches
* Istio 1.11.1 and above
* Istio 1.10.4 and above
* Istio 1.9.8 and above

### Workarounds
A Lua filter may be written to normalize Host header before the authorization check.  This is similar to the Path normalization presented in the [Security Best Practices](https://istio.io/latest/docs/ops/best-practices/security/#case-normalization) guide.

### References
More details can be found in the [Istio Security Bulletin](https://istio.io/latest/news/security/istio-security-2021-008).

### For more information
If you have any questions or comments about this advisory, please email us at istio-security-vulnerability-reports@googlegroups.com

