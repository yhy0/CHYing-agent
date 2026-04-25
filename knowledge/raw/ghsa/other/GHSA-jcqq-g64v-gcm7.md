# Previous ATX is not checked to be the newest valid ATX by Smesher when validating incoming ATX

**GHSA**: GHSA-jcqq-g64v-gcm7 | **CVE**: CVE-2024-34360 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-754

**Affected Packages**:
- **github.com/spacemeshos/go-spacemesh** (go): < 1.5.2-hotfix1
- **github.com/spacemeshos/api** (go): < 1.37.1

## Description

### Impact
Nodes can publish ATXs which reference the incorrect previous ATX of the Smesher that created the ATX. ATXs are expected to form a single chain from the newest to the first ATX ever published by an identity. Allowing Smeshers to reference an earlier (but not the latest) ATX as previous breaks this protocol rule and can serve as an attack vector where Nodes are rewarded for holding their PoST data for less than one epoch but still being eligible for rewards.

### Patches
- API needs to be extended to be able to fetch events from a node that dected malicious behavior of this regard by the node
- go-spacemesh needs to be patched to a) not allow publishing these ATXs any more and b) create malfeasance proofs for identities that published invalid ATXs in the past.

### Workarounds
n/a

### References
Spacemesh protocol whitepaper: https://spacemesh.io/blog/spacemesh-white-paper-1/, specifically sections 4.4.2 ("ATX Contents") and 4.4.3 ("ATX validity")
