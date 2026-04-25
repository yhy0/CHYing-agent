# ipld/go-codec-dagpb panics when processing certain blocks

**GHSA**: GHSA-g3vv-g2j5-45f2 | **CVE**: CVE-2022-2584 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-119

**Affected Packages**:
- **github.com/ipld/go-codec-dagpb** (go): < 1.3.1

## Description

### Impact 
Decoding certain blocks using the go-ipld-prime version of the dag-pb codec (go-codec-dagpb) can cause a panic.  The panic comes from an assumption that the reported link length is accurate, but if the block ends before that reported length then it’s a buffer overread.

### Patches
The issue is fixed in v1.3.1 and above.

Consumers can discover the versions of `go-codec-dagpb` in a module's dependency graph using the following command in the module root:

```go mod graph | grep go-codec-dagpb```

### Workarounds
You can work around this issue without upgrading by recovering panics higher in the call stack of the goroutine that calls the defective code.

### For more information
If you have any questions or comments about this advisory:

* Ask in [IPFS Discord #ipld-chatter](https://discord.gg/ipfs)
* Open an issue in [go-codec-dagpb](https://github.com/ipld/go-codec-dagpb)
