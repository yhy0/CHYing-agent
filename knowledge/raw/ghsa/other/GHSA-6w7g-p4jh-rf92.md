# "Verify All" Returns Success Despite Validation Failures in Singularity

**GHSA**: GHSA-6w7g-p4jh-rf92 | **CVE**: CVE-2020-13846 | **Severity**: high (CVSS 7.5)

**CWE**: N/A

**Affected Packages**:
- **github.com/sylabs/singularity** (go): >= 3.5.0, < 3.6.0

## Description

### Impact

The `--all / -a` option to `singularity verify` returns success even when some objects in a SIF container are not signed, or cannot be verified.

The SIF objects that are not verified are reported in `WARNING` log messages, but a `Container Verified` message and exit code of `0`  are returned.

Workflows that verify a container using `--all / -a` and use the exit code as an indicator of success are vulnerable to running SIF containers that have unsigned, or modified, objects that may be exploited to introduce malicious behavior.

```
$ singularity verify -a image.sif 
WARNING: Missing signature for SIF descriptor 2 (JSON.Generic)
WARNING: Missing signature for SIF descriptor 3 (FS)
Container is signed by 1 key(s):

Verifying partition: Def.FILE:
12045C8C0B1004D058DE4BEDA20C27EE7FF7BA84
[LOCAL]   Unit Test <unit@test.com>
[OK]      Data integrity verified

INFO:    Container verified: image.sif

$ echo $?
0
```


### Patches

Singularity 3.6.0 has a new implementation of sign/verify that fixes this issue.

All users are advised to upgrade to 3.6.0. Note that Singularity 3.6.0 uses a new signature format that is necessarily incompatible with Singularity < 3.6.0 - e.g. Singularity 3.5.3 cannot verify containers signed by 3.6.0.

Version 3.6.0 includes a `--legacy-insecure` flag for the `singularity verify` command, that will perform verification of the older, and insecure, legacy signatures for compatibility with existing containers. This does not guarantee that containers have not been modified since signing, due to other issues in the legacy signature format.

### Workarounds

If you are unable to update to 3.6.0 ensure that you do not rely on the return code of `singularity verify --all / -a` as an indicator of trust in a container.

Note that other issues in the sign/verify implementation in Singularity < 3.6.0 allow additional means to introduce malicious behavior to a signed container.


### For more information

General questions about the impact of the advisory / changes made in the 3.6.0 release can be asked in the:

* [Singularity Slack Channel](https://bit.ly/2m0g3lX)
* [Singularity Mailing List](https://groups.google.com/a/lbl.gov/forum/??sdf%7Csort:date#!forum/singularity)

Any sensitive security concerns should be directed to: security@sylabs.io

See our Security Policy here: https://sylabs.io/security-policy
