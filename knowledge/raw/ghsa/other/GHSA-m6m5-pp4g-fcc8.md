# S3 storage write is not aborted on errors leading to unbounded memory usage

**GHSA**: GHSA-m6m5-pp4g-fcc8 | **CVE**: N/A | **Severity**: high (CVSS 7.5)

**CWE**: CWE-772

**Affected Packages**:
- **github.com/foxcpp/maddy** (go): < 0.5.1

## Description

### Impact

Anyone using storage.blob.s3 introduced in 0.5.0 with storage.imapsql.
```
storage.imapsql local_mailboxes {
  ...
  msg_store s3 {
    ...
  }
}
```

### Patches

The relevant commit is pushed to master and will be included in the 0.5.1 release.

No special handling of the issue has been done due to the small amount of affected users.

### Workarounds

None.

### References

* Original report: https://github.com/foxcpp/maddy/issues/395
* Fix: https://github.com/foxcpp/maddy/commit/07c8495ee4394fabbf5aac4df8aebeafb2fb29d8
