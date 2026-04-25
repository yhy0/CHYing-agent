# RKE2 allows privilege escalation in Windows nodes due to Insecure Access Control Lists

**GHSA**: GHSA-x7xj-jvwp-97rv | **CVE**: N/A | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-269, CWE-732

**Affected Packages**:
- **github.com/rancher/rke2** (go): >= 1.27.0, < 1.27.15
- **github.com/rancher/rke2** (go): >= 1.28.0, < 1.28.11
- **github.com/rancher/rke2** (go): >= 1.29.0, < 1.29.6
- **github.com/rancher/rke2** (go): >= 1.30.0, < 1.30.2

## Description

### Impact

A vulnerability has been identified whereby RKE2 deployments in Windows nodes have weak Access Control Lists (ACL), allowing `BUILTIN\Users` or `NT AUTHORITY\Authenticated Users` to view or edit sensitive files which could lead to privilege escalation.

The affected files include binaries, scripts, configuration and log files:

```
C:\etc\rancher\node\password
C:\var\lib\rancher\rke2\agent\logs\kubelet.log
C:\var\lib\rancher\rke2\data\v1.**.**-rke2r*-windows-amd64-*\bin\*
C:\var\lib\rancher\rke2\bin\*
```

**This vulnerability is exclusive to RKE2 in Windows environments. Linux environments are not affected by it.**

Please consult the associated [MITRE ATT&CK - Technique - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) for further information about this category of attack.


### Patches

Patched versions include RKE2 `1.31.0`, `1.30.2`, `1.29.6`, `1.28.11` and `1.27.15`.

### Workarounds

Users are advised to do a fresh install of their RKE2 Windows nodes using a patched RKE2 version. 
When that is not possible, users can enforce stricter ACLs for all sensitive files affected by this Security Advisory running [this](https://github.com/rancherlabs/support-tools/blob/master/windows-access-control-lists/README.md) PowerShell script as an Administrator on each node.

### References

- [CVE-2023-32197](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32197)
- [Rancher Manager’s GHSA-7h8m-pvw3-5gh4](https://github.com/rancher/rancher/security/advisories/GHSA-7h8m-pvw3-5gh4)

### For more information

If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).

