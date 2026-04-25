# Local Privilege Escalation in cloudflared

**GHSA**: GHSA-hgwp-4vp4-qmm2 | **CVE**: CVE-2020-24356 | **Severity**: high (CVSS 7.8)

**CWE**: CWE-427

**Affected Packages**:
- **github.com/cloudflare/cloudflared** (go): < 0.0.0-20200820025921-9323844ea773

## Description

In `cloudflared` versions < 2020.8.1 (corresponding to 0.0.0-20200820025921-9323844ea773 on pkg.go.dev) on Windows, if an administrator has started `cloudflared` and set it to read configuration files from a certain directory, an unprivileged user can exploit a misconfiguration in order to escalate privileges and execute system-level commands. The misconfiguration was due to the way that `cloudflared` reads its configuration file. One of the locations that `cloudflared` reads from (C:\etc\) is not a secure by default directory due to the fact that Windows does not enforce access controls on this directory without further controls applied. A malformed config.yaml file can be written by any user. Upon reading this config, `cloudflared` would output an error message to a log file defined in the malformed config. The user-controlled log file location could be set to a specific location that Windows will execute when any user logs in.
