# jeecg-boot vulnerable to improper authentication 

**GHSA**: GHSA-6rfv-h5v8-cj7g | **CVE**: CVE-2023-1784 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-287

**Affected Packages**:
- **org.jeecgframework.boot:jeecg-boot-parent** (maven): <= 3.5.0

## Description

A vulnerability was found in jeecg-boot 3.5.0 that affects some unknown processing of the component API Documentation. The manipulation leads to improper authentication because the software does not prove or insufficiently proves that an identity claim is correct when an actor claims to have a given identity. The attack may be initiated remotely and the exploit has been disclosed to the public and may be used.
