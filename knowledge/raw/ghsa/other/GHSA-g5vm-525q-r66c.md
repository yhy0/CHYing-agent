# Velociraptor vulnerable to Missing Authorization

**GHSA**: GHSA-g5vm-525q-r66c | **CVE**: CVE-2023-0242 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-269, CWE-862

**Affected Packages**:
- **www.velocidex.com/golang/velociraptor** (go): < 0.6.7-5

## Description

Rapid7 Velociraptor allows users to be created with different privileges on the server. Administrators are generally allowed to run any command on the server including writing arbitrary files. However, lower privilege users are generally forbidden from writing or modifying files on the server. The VQL copy() function applies permission checks for reading files but does not check for permission to write files. This allows a low privilege user (usually, users with the Velociraptor "investigator" role) to overwrite files on the server, including Velociraptor configuration files. To exploit this vulnerability, the attacker must already have a Velociraptor user account at a low privilege level (at least "analyst") and be able to log into the GUI and create a notebook where they can run the VQL query invoking the copy() VQL function. Typically, most users deploy Velociraptor with limited access to a trusted group (most users will be administrators within the GUI). This vulnerability is associated with program files https://github.Com/Velocidex/velociraptor/blob/master/vql/filesystem/copy.go https://github.Com/Velocidex/velociraptor/blob/master/vql/filesystem/copy.go and program routines copy(). This issue affects Velociraptor versions before 0.6.7-5. Version 0.6.7-5, released January 16, 2023, fixes the issue.
