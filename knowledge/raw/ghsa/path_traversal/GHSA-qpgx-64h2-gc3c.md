# Insecure path traversal in Git Trigger Source can lead to arbitrary file read

**GHSA**: GHSA-qpgx-64h2-gc3c | **CVE**: CVE-2022-25856 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/argoproj/argo-events** (go): < 1.7.1

## Description

### Impact
A path traversal issue was found in the `(g *GitArtifactReader).Read() API. Read()` calls into `(g *GitArtifactReader).readFromRepository()` that opens and reads the file that contains the trigger resource definition:

```go
func (g *GitArtifactReader) readFromRepository(r *git.Repository, dir string)
```

No checks are made on this file at read time, which could lead an attacker to read files anywhere on the system. This could be achieved by either using symbolic links, or putting `../` in the path.

### Patches
A patch for this vulnerability has been released in the following Argo Events version:

v1.7.1

### Credits
Disclosed by [Ada Logics](https://adalogics.com/) in a security audit sponsored by CNCF and facilitated by OSTIF.

### For more information
Open an issue in the [Argo Events issue tracker](https://github.com/argoproj/argo-events/issues) or [discussions](https://github.com/argoproj/argo-events/discussions)
Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-events

