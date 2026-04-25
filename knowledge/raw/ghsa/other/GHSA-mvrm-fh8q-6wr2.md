# Remote Code Execution via path traversal bypass in lollms

**GHSA**: GHSA-mvrm-fh8q-6wr2 | **CVE**: CVE-2024-5443 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-29

**Affected Packages**:
- **lollms** (pip): >= 5.9.0, < 9.5.1

## Description

CVE-2024-4320 describes a vulnerability in the parisneo/lollms software, specifically within the `ExtensionBuilder().build_extension()` function. The vulnerability arises from the `/mount_extension` endpoint, where a path traversal issue allows attackers to navigate beyond the intended directory structure. This is facilitated by the `data.category` and `data.folder` parameters accepting empty strings (`""`), which, due to inadequate input sanitization, can lead to the construction of a `package_path` that points to the root directory. Consequently, if an attacker can create a `config.yaml` file in a controllable path, this path can be appended to the `extensions` list and trigger the execution of `__init__.py` in the current directory, leading to remote code execution. The vulnerability affects versions from 5.9.0, and has been addressed in version 9.5.1.
