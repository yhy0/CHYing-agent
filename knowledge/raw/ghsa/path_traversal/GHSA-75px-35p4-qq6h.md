# Aim External Control of File Name or Path vulnerability

**GHSA**: GHSA-75px-35p4-qq6h | **CVE**: CVE-2024-6829 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-73

**Affected Packages**:
- **aim** (pip): <= 3.19.3

## Description

A vulnerability in aimhubio/aim version 3.19.3 allows an attacker to exploit the `tarfile.extractall()` function to extract the contents of a maliciously crafted tarfile to arbitrary locations on the host server. The attacker can control `repo.path` and `run_hash` to bypass directory existence checks and extract files to unintended locations, potentially overwriting critical files. This can lead to arbitrary data being written to arbitrary locations on the remote tracking server, which could be used for further attacks such as writing a new SSH key to the target server.
