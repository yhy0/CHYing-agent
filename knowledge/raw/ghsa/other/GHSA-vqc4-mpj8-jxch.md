# Grafana Race condition allowing privilege escalation

**GHSA**: GHSA-vqc4-mpj8-jxch | **CVE**: CVE-2022-39328 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-362

**Affected Packages**:
- **github.com/grafana/grafana** (go): >= 9.2.0, < 9.2.4

## Description

Today we are releasing Grafana 9.2.4. Alongside other bug fixes, this patch release includes critical security fixes for CVE-2022-39328.

Release 9.2.4, latest patch, also containing security fix:

- [Download Grafana 9.2.4](https://grafana.com/grafana/download/9.2.4)

Appropriate patches have been applied to [Grafana Cloud](https://grafana.com/cloud) and as always, we closely coordinated with all cloud providers licensed to offer Grafana Pro. They have received early notification under embargo and confirmed that their offerings are secure at the time of this announcement. This is applicable to Amazon Managed Grafana and Azure Managed Grafana as a service offering.

## Privilege escalation

### Summary

Internal security audit identified a race condition in the Grafana codebase, which allowed an unauthenticated user to query an arbitrary endpoint in Grafana.
A race condition in the [HTTP context creation](https://github.com/grafana/grafana/blob/main/pkg/web/router.go#L153) could make a HTTP request being assigned the authentication/authorization middlewares of another call. Under heavy load it is possible that a call protected by a privileged middleware receives instead the middleware of a public query. 
As a result, an unauthenticated user can successfully query protected endpoints.

The CVSS score for this vulnerability is [9.8 Critical](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H&version=3.1)

### Impact

Unauthenticated users can query arbitrary endpoints with malicious intent.

### Impacted versions

All installations for Grafana versions >=9.2.x.

### Solutions and mitigations

To fully address CVE-2022-39328, please upgrade your Grafana instances. 
Appropriate patches have been applied to [Grafana Cloud](https://grafana.com/cloud).

## Reporting security issues

If you think you have found a security vulnerability, please send a report to security@grafana.com. This address can be used for all of Grafana Labs' open source and commercial products (including, but not limited to Grafana, Grafana Cloud, Grafana Enterprise, and grafana.com). We can accept only vulnerability reports at this address. We would prefer that you encrypt your message to us by using our PGP key. The key fingerprint is

F988 7BEA 027A 049F AE8E 5CAA D125 8932 BE24 C5CA

The key is available from keyserver.ubuntu.com.

## Security announcements

We maintain a [security category](https://community.grafana.com/c/support/security-announcements) on our blog, where we will always post a summary, remediation, and mitigation details for any patch containing security fixes.

You can also subscribe to our [RSS feed](https://grafana.com/tags/security/index.xml).
