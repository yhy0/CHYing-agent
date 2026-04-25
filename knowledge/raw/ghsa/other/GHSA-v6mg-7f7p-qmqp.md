# apko Exposure of HTTP basic auth credentials in log output

**GHSA**: GHSA-v6mg-7f7p-qmqp | **CVE**: CVE-2024-36127 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-522, CWE-532

**Affected Packages**:
- **chainguard.dev/apko** (go): < 0.14.5

## Description

### Summary

Exposure of HTTP basic auth credentials from repository and keyring URLs in log output

### Details

There was a handful of instances where the `apko` tool was outputting error messages and log entries where HTTP basic authentication credentials were exposed for one of two reasons:

1. The`%s` verb was used to format a `url.URL` as a string, which includes un-redacted HTTP basic authentication credentials if they are included in the URL.
2. A string URL value (such as from the configuration YAML file supplied used in an apko execution) was never parsed as a URL, so there was no chance of redacting credentials in the logical flow.

apko, as well as its companion library `go-apk`, have been updated to ensure URLs are parsed and redacted before being output as string values.

### PoC

Create a config file like this `apko.yaml`:

```yaml
contents:
  keyring:
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
  repositories:
    - https://me%40example.com:supersecretpassword@localhost:8080/os
  packages:
    - wolfi-base

cmd: /bin/sh -l

archs:
- x86_64
- aarch64
```

Then run:

```shell
apko build apko.yaml latest foo.tar --log-level debug
```

Observe instances of the password being shown verbatim in the log output, such as:

```text
...
DEBU image configuration:
contents:
    repositories:
        - https://me%40example.com:supersecretpassword@localhost:8080/os
    keyring:
        - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
        - wolfi-base
...
```

### Impact

For users accessing keyring or APK repository content using HTTP basic auth, credentials were being logged in plaintext, depending on the user's logging settings. If you use apko in continuous integration jobs, it is likely that the credentials leak via logs of these jobs. Depending on the accessibility of these logs, this could be a company-internal or public leakage of credentials.
