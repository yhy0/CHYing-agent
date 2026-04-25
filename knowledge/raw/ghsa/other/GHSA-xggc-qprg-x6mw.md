# Weave GitOps leaked cluster credentials into logs on connection errors

**GHSA**: GHSA-xggc-qprg-x6mw | **CVE**: CVE-2022-31098 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-200, CWE-209, CWE-532, CWE-538

**Affected Packages**:
- **github.com/weaveworks/weave-gitops** (go): <= 0.8.1-rc.5

## Description

### Impact
A vulnerability in the logging of Weave GitOps could allow an authenticated remote attacker to view sensitive cluster configurations, aka KubeConfg, of registered Kubernetes clusters, including the service account tokens in plain text from Weave GitOps's pod logs on the management cluster. An unauthorized remote attacker can also view these sensitive configurations from external log storage if enabled by the management cluster.

This vulnerability is due to the client factory dumping cluster configurations and their service account tokens when the cluster manager tries to connect to an API server of a registered cluster, and a connection error occurs. An attacker could exploit this vulnerability by either accessing logs of a pod of Weave GitOps, or from external log storage and obtaining all cluster configurations of registered clusters.

A successful exploit could allow the attacker to use those cluster configurations to manage the registered Kubernetes clusters.

### Patches
This vulnerability has been fixed by commit 567356f471353fb5c676c77f5abc2a04631d50ca. Users should upgrade to Weave GitOps core version >= v0.8.1-rc.6 released on 31/05/2022.

### Workarounds
There is no workaround for this vulnerability.

### References
Disclosed by Stefan Prodan, Principal Engineer, Weaveworks.

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [Weave GitOps repository](https://github.com/weaveworks/weave-gitops)
* Email us at [support@weave.works](mailto:support@weave.works)

