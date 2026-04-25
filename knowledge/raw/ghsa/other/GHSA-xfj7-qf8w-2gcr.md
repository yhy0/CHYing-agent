# Rancher 'Audit Log' leaks sensitive information

**GHSA**: GHSA-xfj7-qf8w-2gcr | **CVE**: CVE-2023-22649 | **Severity**: high (CVSS 7.8)

**CWE**: CWE-532

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.6.0, < 2.6.14
- **github.com/rancher/rancher** (go): >= 2.7.0, < 2.7.10
- **github.com/rancher/rancher** (go): >= 2.8.0, < 2.8.2

## Description

### Impact

A vulnerability has been identified which may lead to sensitive data being leaked into Rancher's audit logs. [Rancher Audit Logging](https://ranchermanager.docs.rancher.com/how-to-guides/advanced-user-guides/enable-api-audit-log) is an opt-in feature, only deployments that have it enabled and have [AUDIT_LEVEL](https://ranchermanager.docs.rancher.com/how-to-guides/advanced-user-guides/enable-api-audit-log#audit-log-levels) set to `1 or above` are impacted by this issue.

The leaks might be caught in the audit logs upon these actions:

- Creating cloud credentials or new authentication providers. It is crucial to note that **all** [authentication providers](https://ranchermanager.docs.rancher.com/pages-for-subheaders/authentication-config#external-vs-local-authentication) (such as AzureAD) and [cloud providers](https://ranchermanager.docs.rancher.com/pages-for-subheaders/set-up-cloud-providers) (such as Google) are impacted. 
- Downloading a kubeconfig file from a downstream or a local cluster.
- Logging in/out from Rancher.

The affected data may include the following:

- HTTP headers

Field | Location
-- | --
X-Api-Auth-Header | Request header
X-Api-Set-Cookie-Header | Response header
X-Amz-Security-Token | Request header
credentials | Request body
applicationSecret | Request Body
oauthCredential | Request Body
serviceAccountCredential | Request Body
spKey | Request Body
spCert | Request body
spCert | Response body
certificate | Request body
privateKey | Request body
 
- API Server calls returning `Secret` objects (including sub-types, such as `kubernetes.io/dockerconfigjson`).
- Raw command lines used by agents to connect to the Rancher server which expose sensitive information (e.g. `register ... --token abc`).
- `Kubeconfig` contents when the 'Download KubeConfig' feature is used in the Rancher UI.

The patched versions will redact the sensitive data, replacing it with `[redacted]`, making it safer for consumption. It is recommended that static secrets are rotated after the system is patched, to limit the potential impact of sensitive data being misused due to this vulnerability.

**Note:**
1. The severity of the vulnerability is intricately tied to the logging strategy employed. If logs are kept locally (default configuration), the impact is contained within the system, limiting the exposure.
However, when logs are shipped to an external endpoint, the vulnerability's severity might increase, as resistance against leaks is contingent on the security measures implemented at the external log collector level.
2. The final impact severity for confidentiality, integrity and availability is dependent on the permissions that the leaked credentials have on their own services.


### Patches
Patched versions include releases `2.6.14`, `2.7.10` and `2.8.2`.

### Workarounds
If `AUDIT_LEVEL` `1 or above` is required and you cannot update to a patched Rancher version, ensure that the log is handled appropriately and it is not shared with other users or shipped into a log ingestion solution without the appropriate RBAC enforcement. Otherwise, disabling the Audit feature or decreasing it to the audit level `0`, mitigates the issue.

### For more information

If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).

