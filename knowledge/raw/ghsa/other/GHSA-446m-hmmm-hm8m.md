# Ckan remote code execution and private information access via crafted resource ids

**GHSA**: GHSA-446m-hmmm-hm8m | **CVE**: CVE-2023-32321 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-20

**Affected Packages**:
- **ckan** (pip): < 2.9.9
- **ckan** (pip): = 2.10.0

## Description

Specific vulnerabilities:

* Arbitrary file write in `resource_create` and `package_update` actions, using the `ResourceUploader` object.  Also reachable via `package_create`, `package_revise`, and `package_patch` via calls to `package_update`.
* Remote code execution via unsafe pickle loading, via Beaker's session store when configured to use the file session store backend.
* Potential DOS due to lack of a length check on the resource id.
* Information disclosure: A user with permission to create a resource can access any other resource on the system if they know the id, even if they don't have access to it.
* Resource overwrite: A user with permission to create a resource can overwrite any resource if they know the id, even if they don't have access to it.  

### Impact

A user with permissions to create or edit a dataset can upload a resource with a specially crafted id to write the uploaded file in an arbitrary location. This can be leveraged to Remote Code Execution via Beaker's insecure pickle loading. 

### Patches

All the above listed vulnerabilities have been fixed in CKAN 2.9.9 and CKAN 2.10.1
The patches for CKAN 2.9 should apply easily to previous CKAN versions.
