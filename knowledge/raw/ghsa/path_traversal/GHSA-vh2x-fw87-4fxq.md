# DPanel has an arbitrary file deletion vulnerability in /api/common/attach/delete interface

**GHSA**: GHSA-vh2x-fw87-4fxq | **CVE**: CVE-2025-66292 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/donknap/dpanel** (go): < 1.9.2

## Description

### Summary
DPanel has an arbitrary file deletion vulnerability in the `/api/common/attach/delete` interface. Authenticated users can delete arbitrary files on the server via path traversal.

### Details
When a user logs into the administrative backend, this interface can be used to delete files. The vulnerability lies in the `Delete` function within the `app/common/http/controller/attach.go` file.

The `path` parameter submitted by the user is directly passed to `storage.Local{}.GetSaveRealPath` and subsequently to `os.Remove` without proper sanitization or checking for path traversal characters (`../`).

The vulnerable code snippet:
<img width="487" height="363" alt="image" src="https://github.com/user-attachments/assets/b811de6f-1df1-49f3-af78-ea77bc420804" />


And the helper function in `common/service/storage/local.go` uses `filepath.Join`, which resolves `../` but does not enforce a chroot/jail:
<img width="564" height="66" alt="image" src="https://github.com/user-attachments/assets/84d5a4f7-9054-4e1d-aa6b-6b50c80ba277" />

### PoC
1. Log in to the DPanel dashboard to obtain the `Authorization` token.
2. Send a POST request to delete a file (e.g., `/tmp/1.txt` inside the container).

**Request:**
```http
POST /dpanel/api/common/attach/delete HTTP/1.1
Host: target-ip:8807
Authorization: Bearer <YOUR_TOKEN>
Content-Type: application/x-www-form-urlencoded

path=../../../../../../../../tmp/1.txt
```

<img width="1600" height="940" alt="image" src="https://github.com/user-attachments/assets/40e4d3cb-57f7-4a4e-adcc-a9503af762be" />
<img width="346" height="191" alt="image" src="https://github.com/user-attachments/assets/756c0891-e61b-434c-9386-6e701bbb1a97" />
<img width="1310" height="885" alt="image" src="https://github.com/user-attachments/assets/31c883c2-725e-4618-977c-35fe19adafb1" />
<img width="1009" height="209" alt="image" src="https://github.com/user-attachments/assets/2641fdfb-6d73-4940-bd92-44d748e0e6b7" />
<img width="1265" height="876" alt="image" src="https://github.com/user-attachments/assets/14c67ec8-ec37-4820-90be-a24f58819020" />
