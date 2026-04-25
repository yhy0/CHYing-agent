# Duplicate Advisory: Wildfly Elytron integration susceptible to brute force attacks via CLI

**GHSA**: GHSA-3jxr-23ph-c89g | **CVE**: N/A | **Severity**: high (CVSS 8.1)

**CWE**: CWE-307

**Affected Packages**:
- **org.wildfly.core:wildfly-elytron-integration** (maven): <= 27.0.0.Final

## Description

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-qhp6-6p8p-2rqh. This link is maintained to preserve external references.

### Original Description
A flaw was found in Wildfly Elytron integration. The component does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame, making it more susceptible to brute force attacks via CLI.
