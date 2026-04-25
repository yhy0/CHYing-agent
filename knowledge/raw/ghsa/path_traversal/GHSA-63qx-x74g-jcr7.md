# Path traversal and dereference of symlinks in Argo CD

**GHSA**: GHSA-63qx-x74g-jcr7 | **CVE**: CVE-2022-24348 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-22, CWE-200

**Affected Packages**:
- **github.com/argoproj/argo-cd/v2** (go): < 2.1.9
- **github.com/argoproj/argo-cd/v2** (go): >= 2.2.0, < 2.2.4
- **github.com/argoproj/argo-cd** (go): < 2.1.9

## Description

### Impact

All versions of Argo CD are vulnerable to a path traversal bug that allows to pass arbitrary values files to be consumed by Helm charts. 

Additionally, it is possible to craft special Helm chart packages containing value files that are actually symbolic links, pointing to arbitrary files outside the repository's root directory.

If an attacker with permissions to create or update Applications knows or can guess the full path to a file containing valid YAML, they can create a malicious Helm chart to consume that YAML as values files, thereby gaining access to data they would otherwise have no access to. 

The impact can especially become critical in environments that make use of encrypted value files (e.g. using plugins with git-crypt or SOPS) containing sensitive or confidential data, and decrypt these secrets to disk before rendering the Helm chart.

Also, because any error message from `helm template` is passed back to the user, and these error messages are quite verbose, enumeration of files on the repository server's file system is possible.

### Patches

A patch for this vulnerability has been released in the following Argo CD versions:

* v2.3.0
* v2.2.4
* v2.1.9

We urge users of Argo CD to update their installation to one of the fixed versions as listed above.

### Workarounds

No workaround for this issue.

### References

* https://apiiro.com/blog/malicious-kubernetes-helm-charts-can-be-used-to-steal-sensitive-information-from-argo-cd-deployments
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24348

### For more information

* Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
* Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel `#argo-cd`

### Credits

The path traversal vulnerability was discovered and reported by Moshe Zioni, VP Security Research, [Apiiro](https://www.apiiro.com). 

During the development of a fix for the path traversal vulnerability, the Argo CD team discovered the related issue with symbolic links.

The Argo CD team would like to thank Moshe Zioni for the responsible disclosure, and the constructive discussions during handling this issue!

