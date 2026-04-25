# Permissive Regular Expression in tacquito

**GHSA**: GHSA-p5wf-cmr4-xrwr | **CVE**: N/A | **Severity**: high (CVSS 7.6)

**CWE**: CWE-1333

**Affected Packages**:
- **github.com/facebookincubator/tacquito** (go): < 0.0.0-20241011192817-07b49d1358e6

## Description

### Impact
The CVE is for a software vulnerability. Network admins who have deployed tacquito (or versions of tacquito) in their production environments and use tacquito to perform command authorization for network devices should be impacted.

Tacquito code prior to commit 07b49d1358e6ec0b5aa482fcd284f509191119e2 was performing regex matches on authorized commands and arguments in a more permissive than intended manner. Configured allowed commands/arguments were intended to require a match on the entire string, but instead only enforced a match on a sub-string. This behaviour could potentially allowed unauthorized commands to be executed.

### Patches
The problem has been patched, and users should update to the latest github repo commit to get the patch. 

### Workarounds
Users should be able to add boundary conditions anchors '^' and '$' to their command configs to remediate the vulnerability without the upgrade

