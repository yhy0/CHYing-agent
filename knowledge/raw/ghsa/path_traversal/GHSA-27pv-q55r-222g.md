# Path traversal in github.com/ipfs/go-ipfs

**GHSA**: GHSA-27pv-q55r-222g | **CVE**: CVE-2020-26279 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/ipfs/go-ipfs** (go): < 0.8.0

## Description

### Impact
It is currently possible for path traversal to occur with DAGs containing relative paths during retrieval. This can cause files to be overwritten, or written to incorrect output directories. The issue can only occur when `ipfs get` is done on an affected DAG.

1. The only affected command is `ipfs get`.
2. The gateway is not affected.

### Patches
Traversal fix patched in https://github.com/whyrusleeping/tar-utils/commit/20a61371de5b51380bbdb0c7935b30b0625ac227
`tar-utils` patch applied to go-ipfs via https://github.com/ipfs/go-ipfs/commit/b7ddba7fe47dee5b1760b8ffe897908417e577b2

### Workarounds
Upgrade to go-ipfs 0.8 or later.

### References
Binaries for the patched versions of go-ipfs are available on the IPFS distributions site, https://dist.ipfs.io/go-ipfs

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [go-ipfs](https://github.com/ipfs/go-ipfs)
* Email us at [security@ipfs.io](mailto:security@ipfs.io)
