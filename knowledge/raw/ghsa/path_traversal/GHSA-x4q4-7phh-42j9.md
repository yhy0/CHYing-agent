# Alist vulnerable to Path Traversal in multiple file operation handlers

**GHSA**: GHSA-x4q4-7phh-42j9 | **CVE**: CVE-2026-25161 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/alist-org/alist/v3** (go): < 3.57.0

## Description

### Summary
The application contains a Path Traversal vulnerability (CWE-22) in multiple file operation handlers. An authenticated attacker can bypass directory-level authorisation by injecting traversal sequences into filename components, enabling unauthorised file removal, movement and copying across user boundaries within the same storage mount.

### Details
The application contains a Path Traversal vulnerability (CWE-22) in multiple file operation handlers ([server/handles/fsmanage.go](https://github.com/AlistGo/alist/blob/main/server/handles/fsmanage.go), [server/handles/fsbatch.go](https://github.com/AlistGo/alist/blob/main/server/handles/fsbatch.go), etc.). Filename components in `req.Names`, `renameObject.SrcName`, and `renameObject.NewName` are directly concatenated with validated directories using `stdpath.Join()` or `fmt.Sprintf()`. This allows ".." sequences to bypass path restrictions, enabling users to access other users' files within the same storage mount and perform unauthorized actions such as deletion, renaming, or copying of files.

[FsRemove](https://github.com/AlistGo/alist/blob/b4d9beb49cba399842a54fcc33bc95a4a09b7bd4/server/handles/fsmanage.go#L253-L254):
~~~go
func FsRemove(c *gin.Context) {
	// ...
	for _, name := range req.Names {
		err := fs.Remove(c, stdpath.Join(reqDir, name))
~~~

[FsCopy](https://github.com/AlistGo/alist/blob/b4d9beb49cba399842a54fcc33bc95a4a09b7bd4/server/handles/fsmanage.go#L165-L166):
~~~go
func FsCopy(c *gin.Context) {
	// ...
	for i, name := range req.Names {
		t, err := fs.Copy(c, stdpath.Join(srcDir, name), dstDir, len(req.Names) > i+1)
~~~

[FsBatchRename](https://github.com/AlistGo/alist/blob/b4d9beb49cba399842a54fcc33bc95a4a09b7bd4/server/handles/fsbatch.go#L188-L189):
~~~go
func FsBatchRename(c *gin.Context) {
    // ...
    for _, renameObject := range req.RenameObjects {
        filePath := fmt.Sprintf("%s/%s", reqPath, renameObject.SrcName)  // Vulnerable concatenation ✗
        fs.Rename(c, filePath, renameObject.NewName)
    }
}
~~~


#### PoC
1. Environment setup:
- Storage mount '/shared' configured with multiple users.
- Alice has base path '/shared/alice'.
- Admin has base path '/shared/admin' with private files.
- Both users operate within the same storage mount.

2. Craft Malicious Request:
Alice sends a POST request to _/api/fs/remove_ containing a filename with '../' in it.
~~~bash
curl -X POST -H  "Content-Type: application/json" -d '{"dir":"/","names":["../admin/private.txt"]}' http://localhost:5244/api/fs/remove
~~~

Admin's file is deleted without Alice having authorisation for Admin's directory.

[Video](https://github.com/user-attachments/assets/5789fa36-c82c-4781-a5f7-145f54689ada)


### Impact
This vulnerability enables privilege escalation within shared storage environments. An authenticated attacker with basic file operation permissions (remove/rename/copy/move) can bypass directory-level authorisation controls when multiple users exist within the same storage mount.

#### Attack Requirements:
1. Authenticated user account (not guest)
2. Basic file operation permissions
3. Multi-user environment within the same storage mount

#### Consequences:
1. Unauthorised data access: Read, copy, and exfiltrate files from other users' directories
2. Data destruction: Delete or rename files belonging to other users
3. Access control bypass: Circumvent directory isolation mechanisms
4. Integrity violation: Modify or move files across user boundaries


### Credit
This vulnerability was discovered by:
- XlabAI Team of Tencent Xuanwu Lab
- Atuin Automated Vulnerability Discovery Engine

If there are questions regarding the vulnerability details, please feel free to reach out for further discussion at xlabai@tencent.com.
