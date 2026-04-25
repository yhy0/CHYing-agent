# Rancher cloud credentials can be used through proxy API by users without access

**GHSA**: GHSA-gqf8-rvrh-g7w6 | **CVE**: CVE-2021-25320 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-284

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.2.0, < 2.4.16
- **github.com/rancher/rancher** (go): >= 2.5.0, < 2.5.9

## Description

A vulnerability was discovered in Rancher 2.2.0 through the aforementioned patched versions, where cloud credentials weren't being properly validated through the Rancher API. Specifically through a proxy designed to communicate with cloud providers. Any Rancher user that was logged-in and aware of a cloud-credential ID that was valid for a given cloud provider, could call that cloud provider's API through the proxy API, and the cloud-credential would be attached. The exploit is limited to valid Rancher users. There is not a direct mitigation outside of upgrading to the patched Rancher versions.
