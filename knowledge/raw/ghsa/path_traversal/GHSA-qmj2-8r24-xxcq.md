# OpenList vulnerable to Path Traversal in file copy and remove handlers

**GHSA**: GHSA-qmj2-8r24-xxcq | **CVE**: CVE-2026-25059 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/OpenListTeam/OpenList/v4** (go): < 4.1.10

## Description

### Summary
The application contains a Path Traversal vulnerability (CWE-22) in multiple file operation handlers. An authenticated attacker can bypass directory-level authorisation by injecting traversal sequences into filename components, enabling unauthorised file removal and copying across user boundaries within the same storage mount.

### Details
The application contains a Path Traversal vulnerability (CWE-22) in multiple file operation handlers in *server/handles/fsmanage.go*. Filename components in `req.Names` are directly concatenated with validated directories using `stdpath.Join`. This allows ".." sequences to bypass path restrictions, enabling users to access other users' files within the same storage mount and perform unauthorized actions such as deletion, renaming, or copying of files.

[FsRemove](https://github.com/OpenListTeam/OpenList/blob/5db2172ed681346b69ed468c73c1f01b6ed455ea/server/handles/fsmanage.go#L284-L285):
~~~
func FsRemove(c *gin.Context) {
	// ...
	for _, name := range req.Names {
		err := fs.Remove(c, stdpath.Join(reqDir, name))
~~~

[FsCopy](https://github.com/OpenListTeam/OpenList/blob/5db2172ed681346b69ed468c73c1f01b6ed455ea/server/handles/fsmanage.go#L163-L164):
~~~
func FsCopy(c *gin.Context) {
	// ...
	if !req.Overwrite {
		for _, name := range req.Names {
			if res, _ := fs.Get(c.Request.Context(), stdpath.Join(dstDir, name), &fs.GetArgs{NoLog: true}); res != nil {
~~~


### PoC
Scenario:​ A normal user ("alice") bypasses directory restrictions to read files outside her authorized path.

Environment setup:
- Local storage mount as '/local'.
- An admin file "adminsecret.txt" is placed under /local
- Alice has base path '/local/alice'.


https://github.com/user-attachments/assets/5d73bbec-29e5-4c52-8af3-4c70b26d9d0e



### Impact
This vulnerability enables privilege escalation within shared storage environments. An authenticated attacker with basic file operation permissions (remove/copy) can bypass directory-level authorisation controls when multiple users exist within the same storage mount.

Attack Requirements:
- Authenticated user account (not guest)
- Basic file operation permissions (remove/copy)
- Multi-user environment within the same storage mount
- Knowledge (or ability to guess) the target file's name and path

Consequences:
- Unauthorised data access: Read, copy, and exfiltrate files from other users' directories
- Data destruction: Delete files belonging to other users

### Note

This vulnerability was discovered by:
- XlabAI Team of Tencent Xuanwu Lab
- Atuin Automated Vulnerability Discovery Engine

CVE and credit are preferred.

If users have any questions regarding the vulnerability details, please feel free to reach out for further discussion. Email [xlabai@tencent.com](mailto:xlabai@tencent.com).

The security industry standard [90+30 disclosure policy](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html) is followed. Should the aforementioned vulnerabilities remain unfixed after 90 days of submission, all information about the issues will be publicly disclosed.
