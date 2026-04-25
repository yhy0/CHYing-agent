# parisneo/lollms Local File Inclusion (LFI) attack

**GHSA**: GHSA-vqwr-q6cc-c242 | **CVE**: CVE-2024-4315 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-22

**Affected Packages**:
- **lollms** (pip): < 9.5.0

## Description

parisneo/lollms version 9.5 is vulnerable to Local File Inclusion (LFI) attacks due to insufficient path sanitization. The `sanitize_path_from_endpoint` function fails to properly sanitize Windows-style paths (backward slash `\`), allowing attackers to perform directory traversal attacks on Windows systems. This vulnerability can be exploited through various routes, including `personalities` and `/del_preset`, to read or delete any file on the Windows filesystem, compromising the system's availability.
