# Spinnaker clouddriver and orca URL validation bypass via underscores in hostnames

**GHSA**: GHSA-8r8j-gfhg-fw38 | **CVE**: CVE-2026-25534 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-918

**Affected Packages**:
- **io.spinnaker.clouddriver:clouddriver-artifacts** (maven): < 2025.2.4
- **io.spinnaker.clouddriver:clouddriver-artifacts** (maven): >= 2025.3.0, < 2025.3.1
- **io.spinnaker.clouddriver:clouddriver-artifacts** (maven): >= 2025.4.0, < 2025.4.1
- **io.spinnaker.orca:orca-core** (maven): < 2025.2.4
- **io.spinnaker.orca:orca-core** (maven): >= 2025.3.0, < 2025.3.1
- **io.spinnaker.orca:orca-core** (maven): >= 2025.4.0, < 2025.4.1

## Description

### Impact
Spinnaker updated URL Validation logic on user input to provide sanitation on user inputted URLs for clouddriver.  However, they missed that Java URL objects do not correctly handle underscores on parsing.  This led to a bypass of the previous CVE (CVE-2025-61916) through the use of carefully crafted URLs.  Note, Spinnaker found this not just in that CVE, but in the existing URL validations in Orca fromUrl expression handling.  This CVE impacts BOTH artifacts as a result.   

### Patches
This has been merged and will be available in versions 2025.4.1, 2025.3.1, 2025.2.4 and 2026.0.0.  

### Workarounds
You can disable the various artifacts on this system to work around these limits.
