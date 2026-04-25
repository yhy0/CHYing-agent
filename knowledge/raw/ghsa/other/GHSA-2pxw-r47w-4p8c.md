# Privilege Escalation on Linux/MacOS

**GHSA**: GHSA-2pxw-r47w-4p8c | **CVE**: CVE-2023-28434 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-269

**Affected Packages**:
- **github.com/minio/minio** (go): < 0.0.0-202303200415

## Description

### Impact
An attacker can use crafted requests to bypass metadata bucket name checking and put an object into any bucket while processing `PostPolicyBucket`. To carry out this attack, the attacker requires credentials with `arn:aws:s3:::*` permission, as well as enabled Console API access.

### Patches
```
commit 67f4ba154a27a1b06e48bfabda38355a010dfca5
Author: Aditya Manthramurthy <donatello@users.noreply.github.com>
Date:   Sun Mar 19 21:15:20 2023 -0700

    fix: post policy request security bypass (#16849)
```

### Workarounds
Browser API access must be enabled turning off `MINIO_BROWSER=off` allows for this workaround.

### References
The vulnerable code:
```go
// minio/cmd/generic-handlers.go
func setRequestValidityHandler(h http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // ...
    // For all other requests reject access to reserved buckets
    bucketName, _ := request2BucketObjectName(r)
    if isMinioReservedBucket(bucketName) || isMinioMetaBucket(bucketName) {
      if !guessIsRPCReq(r) && !guessIsBrowserReq(r) && !guessIsHealthCheckReq(r) && !guessIsMetricsReq(r) && !isAdminReq(r) && !isKMSReq(r) {
        if ok {
          tc.FuncName = "handler.ValidRequest"
          tc.ResponseRecorder.LogErrBody = true
        }
        writeErrorResponse(r.Context(), w, errorCodes.ToAPIErr(ErrAllAccessDisabled), r.URL)
        return
      }
    }
    // ...
```
