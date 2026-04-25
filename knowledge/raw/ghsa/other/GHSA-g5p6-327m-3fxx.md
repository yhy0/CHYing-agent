# Talos Linux ships runc vulnerable to the escape to the host attack

**GHSA**: GHSA-g5p6-327m-3fxx | **CVE**: N/A | **Severity**: high (CVSS 8.6)

**CWE**: N/A

**Affected Packages**:
- **github.com/siderolabs/talos** (go): >= 1.6.0, < 1.6.4
- **github.com/siderolabs/talos** (go): < 1.5.6

## Description

### Impact

Snyk has discovered a vulnerability in all versions of runc <=1.1.11, as used by the Docker engine, along with other containerization technologies such as Kubernetes. Exploitation of this issue can result in container escape to the underlying host OS, either through executing a malicious image or building an image using a malicious Dockerfile or upstream image (i.e., when using FROM). This issue has been assigned the CVE-2024-21626.

### Patches

`runc` runtime was updated to 1.1.12 in Talos v1.5.6 and v1.6.4.

### Workarounds

Inspect the workloads running on the cluster to make sure they are not trying to exploit the vulnerability.

### References

* [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)
* [Vulnerability: runc process.cwd and leaked fds container breakout](https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout/)

