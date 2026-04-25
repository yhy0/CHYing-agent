# Gitops Run insecure communication

**GHSA**: GHSA-89qm-wcmw-3mgg | **CVE**: CVE-2022-23509 | **Severity**: high (CVSS 7.4)

**CWE**: CWE-200, CWE-319

**Affected Packages**:
- **github.com/weaveworks/weave-gitops** (go): <= 0.11.0

## Description

### Impact
GitOps run has a local S3 bucket which it uses for synchronising files that are later applied against a Kubernetes cluster. The communication between GitOps Run and the local s3 bucket is not encrypted. 

This allows privileged users or process to tap the local traffic to gain information permitting access to the s3 bucket. From that point, it would be possible to alter the bucket content, resulting in changes in the Kubernetes cluster's resources(e.g. CVE-2022-23508).

### Patches
This vulnerability has been fixed by commits [ce2bbff](https://github.com/weaveworks/weave-gitops/pull/3106/commits/ce2bbff0a3609c33396050ed544a5a21f8d0797f) and [babd915](https://github.com/weaveworks/weave-gitops/pull/3098/commits/babd91574b99b310b84aeec9f8f895bd18acb967). Users should upgrade to Weave GitOps version >= v0.12.0 released on 08/12/2022.

### Workarounds
There is no workaround for this vulnerability.

### References
Disclosed by Paulo Gomes, Senior Software Engineer, Weaveworks.

### For more information
If you have any questions or comments about this advisory:
- Open an issue in [Weave GitOps repository](https://github.com/weaveworks/weave-gitops)
- Email us at [support@weave.works](mailto:support@weave.works)

