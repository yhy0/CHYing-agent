# Path traversal and improper access control allows leaking out-of-bound files from Argo CD repo-server

**GHSA**: GHSA-r9cr-hvjj-496v | **CVE**: CVE-2022-24730 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-22, CWE-284

**Affected Packages**:
- **github.com/argoproj/argo-cd** (go): >= 1.3.0, < 2.1.11
- **github.com/argoproj/argo-cd** (go): >= 2.2.0, < 2.2.6
- **github.com/argoproj/argo-cd** (go): >= 2.3.0-rc1, < 2.3.0

## Description

### Impact

All unpatched versions of Argo CD starting with v1.3.0 are vulnerable to a path traversal bug, compounded by an improper access control bug, allowing a malicious user with read-only repository access to leak sensitive files from Argo CD's repo-server.

A malicious Argo CD user who has been granted [`get` access for a repository](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/#rbac-resources-and-actions) containing a Helm chart can craft an API request to the `/api/v1/repositories/{repo_url}/appdetails` endpoint to leak the contents of out-of-bounds files from the repo-server.

The malicious payload would reference an out-of-bounds file, and the contents of that file would be returned as part of the response. Contents from a non-YAML file may be returned as part of an error message. The attacker would have to know or guess the location of the target file.

Sensitive files which could be leaked include files from other Applications' source repositories (potentially decrypted files, if you are using a decryption plugin) or any secrets which have been mounted as files on the repo-server.

### Patches

A patch for this vulnerability has been released in the following Argo CD versions:

* v2.3.0
* v2.2.6
* v2.1.11

The patches do two things:
 1) prevent path traversal
 2) limit `/api/v1/repositories/{repo_url}/appdetails` access to users who either A) have been granted Application `create` privileges or B) have been granted Application `get` privileges _and_ are requesting details for a `repo_url` that has already been used for the given Application

### Workarounds

The only certain way to avoid the vulnerability is to upgrade. 

To mitigate the problem, you can 
* avoid storing secrets in git
* avoid mounting secrets as files on the repo-server
* avoid decrypting secrets into files on the repo-server
* carefully [limit who has `get` access for repositories](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/#rbac-resources-and-actions)

### References

* [Security documentation for the repo-server component](https://argo-cd.readthedocs.io/en/stable/operator-manual/security/#git-helm-repositories)
* [Argo CD RBAC configuration documentation](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/#)

### For more information

Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd

