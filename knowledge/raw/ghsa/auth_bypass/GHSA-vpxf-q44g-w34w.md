# Sealos billing system permission control defect

**GHSA**: GHSA-vpxf-q44g-w34w | **CVE**: CVE-2023-36815 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-287, CWE-862

**Affected Packages**:
- **github.com/labring/sealos** (go): <= 4.2.0

## Description

### Summary

There is a permission flaw in the Sealos billing system, which allows users to control the recharge resource account. sealos. io/v1/Payment, resulting in the ability to recharge any amount of 1 RMB.

### Details

The reason is that sealos is in arrears. Egg pain, we can't create a terminal anymore. Let's charge for it:

Then it was discovered that the charging interface had returned all resource information. Unfortunately, based on previous vulnerability experience, the namespace of this custom resource is still under the current user's control and may have permission to correct it.

### PoC
disable by publish

### Impact

+ sealos public cloud user
+ CWE-287 Improper Authentication
