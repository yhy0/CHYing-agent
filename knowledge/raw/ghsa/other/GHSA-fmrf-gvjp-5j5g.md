# Improper Privilege Management in Cilium

**GHSA**: GHSA-fmrf-gvjp-5j5g | **CVE**: CVE-2022-29179 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-269

**Affected Packages**:
- **github.com/cilium/cilium** (go): >= 1.11.0, < 1.11.5
- **github.com/cilium/cilium** (go): >= 1.10.0, < 1.10.11
- **github.com/cilium/cilium** (go): < 1.9.16

## Description

### Impact

If an attacker is able to perform a container escape of a container running as root on a host where Cilium is installed, the attacker can leverage Cilium's Kubernetes service account to gain access to cluster privileges that are more permissive than what is minimally required to operate Cilium. In affected releases, this service account had access to modify and delete `Pod` and `Node` resources. 

### Patches

The problem has been fixed and is available on versions >=1.9.16, >=1.10.11, >=1.11.5

### Workarounds

There are no workarounds available.

### Acknowledgements

The Cilium community has worked together with members of Isovalent, Amazon and Palo Alto Networks to prepare these mitigations.  Special thanks to Micah Hausler (AWS), Robert Clark (AWS), Yuval Avrahami (Palo Alto Networks), and Shaul Ben Hai (Palo Alto Networks) for their cooperation.

### For more information

If you have any questions or comments about this advisory:

Email us at [security@cilium.io](mailto:security@cilium.io)
