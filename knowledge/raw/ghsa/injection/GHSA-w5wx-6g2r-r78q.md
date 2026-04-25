# Nuclei allows unsigned code template execution through workflows

**GHSA**: GHSA-w5wx-6g2r-r78q | **CVE**: CVE-2024-27920 | **Severity**: high (CVSS 7.4)

**CWE**: CWE-78

**Affected Packages**:
- **github.com/projectdiscovery/nuclei/v3** (go): >= 3.0.0, < 3.2.0

## Description

### Overview
A significant security oversight was identified in Nuclei v3, involving the execution of unsigned code templates through workflows. This vulnerability specifically affects users utilizing custom workflows, potentially allowing the execution of malicious code on the user's system. This advisory outlines the impacted users, provides details on the security patch, and suggests mitigation strategies.

### Affected Users
1. **CLI Users:** Those executing custom workflows from untrusted sources. This includes workflows authored by third parties or obtained from unverified repositories.
2. **SDK Users:** Developers integrating Nuclei into their platforms, particularly if they permit the execution of custom workflows by end-users.

### Security Patch
The vulnerability is addressed in Nuclei v3.2.0. Users are strongly recommended to update to this version to mitigate the security risk.

### Mitigation
- **Immediate Upgrade:** The primary recommendation is to upgrade to Nuclei v3.2.0, where the vulnerability has been patched.
- **Avoid Untrusted Workflows:** As an interim measure, users should refrain from using custom workflows if unable to upgrade immediately. Only trusted, verified workflows should be executed.

### Details
The vulnerability stems from an oversight in the workflow execution mechanism, where unsigned code templates could be executed, bypassing the security measures intended to authenticate the integrity and source of the templates. This issue is isolated to workflow executions and does not affect direct template executions.

### Workarounds
The only effective workaround, aside from upgrading, is to avoid the use of custom workflows altogether. This approach limits functionality but ensures security until the upgrade can be performed.

### Acknowledgements
We extend our sincere gratitude to @gpc1996 for their diligence in identifying and reporting this vulnerability.

### References
- Security Patch Pull Request: [GitHub PR #4822](https://github.com/projectdiscovery/nuclei/pull/4822)
- Workflows Overview: [Nuclei Workflows Documentation](https://docs.projectdiscovery.io/templates/workflows/overview)
- Code Template Reference: [Nuclei Code Protocols Documentation](https://docs.projectdiscovery.io/templates/protocols/code)
- Template Signing Reference: [Nuclei Template Signing Documentation](https://docs.projectdiscovery.io/templates/reference/template-signing)
