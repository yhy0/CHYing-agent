# Rancher allows privilege escalation in Windows nodes due to Insecure Access Control Lists

**GHSA**: GHSA-7h8m-pvw3-5gh4 | **CVE**: CVE-2023-32197 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-269, CWE-732

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.7.0, < 2.8.9
- **github.com/rancher/rancher** (go): >= 2.9.0, < 2.9.3

## Description

### Impact

A vulnerability has been identified whereby Rancher Manager deployments containing Windows nodes have weak Access Control Lists (ACL), allowing `BUILTIN\Users` or `NT AUTHORITY\Authenticated Users` to view or edit sensitive files which could lead to privilege escalation.

The affected files include binaries, scripts, configuration and log files:

```
C:\etc\rancher\wins\config
C:\var\lib\rancher\agent\rancher2_connection_info.json
C:\etc\rancher\rke2\config.yaml.d\50-rancher.yaml
C:\var\lib\rancher\agent\applied\*-*-applied.plan
C:\usr\local\bin\rke2
C:\var\lib\rancher\capr\idempotence\idempotent.sh
```

RKE2 nodes expand the list to include the files below:

```
C:\etc\rancher\node\password
C:\var\lib\rancher\rke2\agent\logs\kubelet.log
C:\var\lib\rancher\rke2\data\v1.**.**-rke2r*-windows-amd64-*\bin\*
C:\var\lib\rancher\rke2\bin\*
```

**This vulnerability is exclusive to deployments that contain Windows nodes. Linux-only environments are not affected by it.**

Please consult the associated [MITRE ATT&CK - Technique - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) for further information about this category of attack.

### Patches

Patched versions include Rancher Manager `2.8.9` and `2.9.3`. For RKE2 Windows nodes, please refer to its [specific advisory](https://github.com/rancher/rke2/security/advisories/GHSA-x7xj-jvwp-97rv). No patches are available for 2.7, therefore users are urged to upgrade to newer minor versions or to apply the manual workaround below.


### Workarounds

Users are advised to upgrade to a patched version of Rancher Manager. When that is not possible, users can enforce stricter ACLs for all sensitive files affected by this Security Advisory running [this](https://github.com/rancherlabs/support-tools/blob/master/windows-access-control-lists/README.md) PowerShell script as an Administrator on each node.


### References

- [CVE-2023-32197](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32197)
- [RKE2’s GHSA-x7xj-jvwp-97rv](https://github.com/rancher/rke2/security/advisories/GHSA-x7xj-jvwp-97rv)

### For more information

If you have any questions or comments about this advisory:
- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
