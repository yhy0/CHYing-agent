# pgadmin4 has a Meta-Command Filter Command Execution

**GHSA**: GHSA-fxmw-jcgr-w44v | **CVE**: CVE-2025-13780 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-77, CWE-94

**Affected Packages**:
- **pgadmin4** (pip): < 9.11

## Description

The PLAIN restore meta-command filter introduced in pgAdmin as part of the fix for CVE-2025-12762 does not detect meta-commands when a SQL file begins with a UTF-8 Byte Order Mark (EF BB BF) or other special byte sequences. The implemented filter uses the function `has_meta_commands()`, which scans raw bytes using a regular expression. The regex does not treat the bytes as ignorable, so meta-commands such as `\\!` remain undetected. When pgAdmin invokes psql with --file, psql strips the bytes and executes the command. This can result in remote command execution during a restore operation.
