# Nuclei Path Traversal vulnerability

**GHSA**: GHSA-2xx4-jj5v-6mff | **CVE**: CVE-2023-37896 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/projectdiscovery/nuclei/v2** (go): < 2.9.9
- **github.com/projectdiscovery/nuclei** (go): < 2.9.9

## Description

## Overview

We have identified and addressed a security issue in the Nuclei project that affected users utilizing Nuclei as **Go code (SDK)** running **custom templates**. This issue did not affect CLI users. The problem was related to sanitization issues with payloads loading in `sandbox` mode.

## Details

In the previous versions, there was a potential risk with payloads loading in sandbox mode. The issue occurred due to relative paths not being converted to absolute paths before doing the check for `sandbox` flag allowing arbitrary files to be read on the filesystem in certain cases when using Nuclei from `Go` SDK implementation. 

This issue has been fixed in the latest release, v2.9.9. We have also enabled sandbox by default for filesystem loading. This can be optionally disabled if required.

The `-sandbox` option has been **deprecated** and is now divided into two new options: `-lfa` (allow local file access) which is disabled by default and `-lna` (restrict local network access) which can be optionally disabled by user. The `-lfa` allows file (payload) access anywhere on the system (disabling sandbox effectively), and `-lna` blocks connections to the local/private network.

## Affected Versions

This issue affected all versions of Nuclei prior to v2.9.9.

## Patches

We recommend all users upgrade to the latest version, [v2.9.9](https://github.com/projectdiscovery/nuclei/releases/tag/v2.9.9), which includes the security fix.

### References

- [patch](https://github.com/projectdiscovery/nuclei/pull/3927)
- [releases](https://github.com/projectdiscovery/nuclei/releases/tag/v2.9.9)

## Acknowledgments

We would like to thank **keomutchoiboi** who reported this issue to us via our security email, [security@projectdiscovery.io](mailto:security@projectdiscovery.io). We appreciate the responsible disclosure of this issue.
