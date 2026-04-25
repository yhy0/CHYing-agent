# Kyverno's PolicyException objects can be created in any namespace by default

**GHSA**: GHSA-qjvc-p88j-j9rm | **CVE**: CVE-2024-48921 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-285, CWE-863

**Affected Packages**:
- **github.com/kyverno/kyverno** (go): < 1.13.0

## Description

### Summary
A kyverno ClusterPolicy, ie. "disallow-privileged-containers," can be overridden by the creation of a PolicyException in a random namespace.

### Details
By design, PolicyExceptions are consumed from any namespace. Administrators may not recognize that this allows users with privileges to non-kyverno namespaces to create exceptions.

### PoC
1. Administrator creates "disallow-privileged-containers" ClusterPolicy that applies to resources in the namespace "ubuntu-restricted"
2. Cluster user creates a PolicyException object for "disallow-privileged-containers" in namespace "ubuntu-restricted"
3. Cluster user creates a pod with a privileged container in "ubuntu-restricted" 
4. Cluster user escalates to root on the node from the privileged container

### Impact
Administrators attempting to enforce cluster security through kyverno policies, but that allow less privileged users to create resources
