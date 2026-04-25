# b3log Wide unauthenticated file access

**GHSA**: GHSA-6452-jr93-r5qm | **CVE**: CVE-2019-13915 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-59, CWE-74

**Affected Packages**:
- **github.com/b3log/wide** (go): < 1.6.0

## Description

b3log Wide before 1.6.0 allows three types of attacks to access arbitrary files. First, the attacker can write code in the editor, and compile and run it approximately three times to read an arbitrary file. Second, the attacker can create a symlink, and then place the symlink into a ZIP archive. An unzip operation leads to read access, and write access (depending on file permissions), to the symlink target. Third, the attacker can import a Git repository that contains a symlink, similarly leading to read and write access.
