# Minio vulnerable to Privilege Escalation on Windows via Path separator manipulation

**GHSA**: GHSA-w23q-4hw3-2pp6 | **CVE**: CVE-2023-28433 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-668

**Affected Packages**:
- **github.com/minio/minio** (go): < 0.0.0-202303200735

## Description

### Impact
All users on Windows are impacted. MinIO fails to filter the `\` character, which allows for arbitrary object placement across
buckets. As a result, a user with low privileges, such as an access key, service account, or STS credential, which only has permission to `PutObject` in a specific bucket, can create an admin user.

### Patches
There are two patches that fix this problem comprehensively

```
commit b3c54ec81e0a06392abfb3a1ffcdc80c6fbf6ebc
Author: Harshavardhana <harsha@minio.io>
Date:   Mon Mar 20 13:16:00 2023 -0700

    reject object names with '\' on windows (#16856)
```

```
commit 8d6558b23649f613414c8527b58973fbdfa4d1b8
Author: Harshavardhana <harsha@minio.io>
Date:   Mon Mar 20 00:35:25 2023 -0700

    fix: convert '\' to '/' on windows (#16852)
```

### Workarounds
There are no known workarounds

### References
The vulnerable code:
```go
// minio/cmd/generic-handlers.go
// Check if the incoming path has bad path components,
// such as ".." and "."
// SlashSeparator -> /
// dotdotComponent -> ..
// dotComponent -> .
func hasBadPathComponent(path string) bool {
  path = strings.TrimSpace(path)
  for _, p := range strings.Split(path, SlashSeparator) {
    switch strings.TrimSpace(p) {
    case dotdotComponent:
      return true
    case dotComponent:
      return true
    }
  }
  return false
}
```

