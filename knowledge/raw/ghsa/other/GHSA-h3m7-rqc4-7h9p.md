# Integer overflow in chunking helper causes dispatching to miss elements or panic

**GHSA**: GHSA-h3m7-rqc4-7h9p | **CVE**: CVE-2024-27101 | **Severity**: high (CVSS 7.3)

**CWE**: N/A

**Affected Packages**:
- **github.com/authzed/spicedb** (go): < 1.29.2

## Description

Any SpiceDB cluster with any schema where a resource being checked has more than 65535 relationships for the same resource and subject type is affected by this problem.

The issue may also lead to a panic rendering the server unavailable

The following API methods are affected:
- [CheckPermission](https://buf.build/authzed/api/docs/main:authzed.api.v1#authzed.api.v1.PermissionsService.CheckPermission)
- [BulkCheckPermission](https://buf.build/authzed/api/docs/main:authzed.api.v1#authzed.api.v1.ExperimentalService.BulkCheckPermission)
- [LookupSubjects](https://buf.build/authzed/api/docs/main:authzed.api.v1#authzed.api.v1.PermissionsService.LookupSubjects)

#### Impact

Permission checks that are expected to be allowed are instead denied, and lookup subjects will return fewer subjects than expected.

#### Workarounds

There is no workaround other than making sure that the SpiceDB cluster does not have very wide relations, with the maximum value being the maximum value of an 16-bit unsigned integer

#### Remediations

- AuthZed Dedicated customers: No action. AuthZed has upgraded all deployments.
- AuthZed Serverless customers: No Action. AuthZed has upgraded all deployments.
- AuthZed Enterprise customers: Upgrade to [v1.29.2-hotfix-enterprise.v1.hotfix.v1](https://github.com/authzed-enterprise/src/pkgs/container/spicedb-enterprise/182719614?tag=v1.29.2-hotfix-enterprise.v1.hotfix.v1)
 - Open Source users: Upgrade to v1.29.2
