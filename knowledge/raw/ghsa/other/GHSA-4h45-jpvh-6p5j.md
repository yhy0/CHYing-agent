# Rancher affected by unauthenticated Denial of Service

**GHSA**: GHSA-4h45-jpvh-6p5j | **CVE**: CVE-2024-58259 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.12.0, < 2.12.1
- **github.com/rancher/rancher** (go): >= 2.11.0, < 2.11.5
- **github.com/rancher/rancher** (go): >= 2.10.0, < 2.10.9
- **github.com/rancher/rancher** (go): >= 2.9.0, < 2.9.11
- **github.com/rancher/rancher** (go): < 0.0.0-20250813072957-aee95d4e2a41

## Description

### Impact
A vulnerability has been identified within Rancher Manager in which it did not enforce request body size limits on certain public (unauthenticated) and authenticated API endpoints. This allows a malicious user to exploit this by sending excessively large payloads, which are fully loaded into memory during processing. This could result in:
- Denial of Service (DoS): The server process may crash or become unresponsive when memory consumption exceeds available resources.
- Unauthenticated and authenticated exploitation: While the issue was initially observed in unauthenticated `/v3-public/*` endpoints, the absence of request body size limits also affected several authenticated APIs, broadening the potential attack surface. It's worth noting that other areas in Rancher do implement safeguards: requests proxied to Kubernetes APIs are subject to built-in size limits enforced by the [Kubernetes API server itself](https://github.com/kubernetes/kubernetes/blob/v1.33.4/staging/src/k8s.io/apiserver/pkg/server/config.go#L465), and Norman-based endpoints parse input with [predefined size caps](https://github.com/rancher/norman/blob/41dfae2f1a640c5ac9304e8b51e45a0f52cbdbb9/parse/read_input.go#L20-L31). However, the absence of similar protections in other Rancher APIs increased the risk of denial-of-service (DoS) scenarios in certain contexts.

By sending large binary or text payloads to vulnerable endpoints, a malicious actor could disrupt Rancher’s availability, impacting both administrative and user operations across managed clusters.
 
Please consult the associated  [MITRE ATT&CK - Technique - Network Denial of Service](https://attack.mitre.org/techniques/T1498/) for further information about this category of attack.

### Patches
This vulnerability is addressed by adding a default limit of `1MiB` and a setting in case this value needs to be increased.

Patched versions of Rancher include releases `v2.12.1`, `v2.11.5`, `v2.10.9` and `v2.9.12`.

### Workarounds
If you can't upgrade to a fixed version, please make sure that you are manually setting the request body size limits. For example, using nginx-ingress controller and only allowing requests via the ingress. For reference on how to configure the limit manually, please consult the [Knowledge Base](https://www.suse.com/support/kb/doc/?id=000021309).

### References
If you have any questions or comments about this advisory:
- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
