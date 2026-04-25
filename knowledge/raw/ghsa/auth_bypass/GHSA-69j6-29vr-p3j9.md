# Authentication bypass for viewing and deletions of snapshots

**GHSA**: GHSA-69j6-29vr-p3j9 | **CVE**: CVE-2021-39226 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-287, CWE-862

**Affected Packages**:
- **github.com/grafana/grafana** (go): < 7.5.11
- **github.com/grafana/grafana** (go): >= 8.0.0, < 8.1.6

## Description

Today we are releasing Grafana 7.5.11, and 8.1.6. These patch releases include an important security fix for an issue that affects all Grafana versions from 2.0.1.

[Grafana Cloud](https://grafana.com/cloud) instances have already been patched and an audit did not find any usage of this attack vector. [Grafana Enterprise](https://grafana.com/products/enterprise) customers were provided with updated binaries under embargo.

8.1.5 contained a single fix for bar chart panels. We believe that users can expedite deployment by moving from 8.1.4 to 8.1.6 directly.

## CVE-2021-39226 Snapshot authentication bypass

### Summary

CVSS Score: 9.8 Critical
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

We received a security report to [security@grafana.com](mailto:security@grafana.com) on 2021-09-15 about a vulnerability in Grafana regarding the snapshot feature. It was later identified as affecting Grafana versions from 2.0.1 to 8.1.6. [CVE-2021-39226](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39226) has been assigned to this vulnerability.

### Impact
Unauthenticated and authenticated users are able to view the snapshot with the lowest database key by accessing the literal paths:

* `/dashboard/snapshot/:key`, or
* `/api/snapshots/:key`

If the snapshot "public_mode" configuration setting is set to true (vs default of false), unauthenticated users are able to delete the snapshot with the lowest database key by accessing the literal path:

* `/api/snapshots-delete/:deleteKey`

Regardless of the snapshot "public_mode" setting, authenticated users are able to delete the snapshot with the lowest database key by accessing the literal paths:

* `/api/snapshots/:key`, or
* `/api/snapshots-delete/:deleteKey`

The combination of deletion and viewing enables a complete walk through all snapshot data while resulting in complete snapshot data loss.

### Attack audit

While we can not guarantee that the below will identify all attacks, if you do find something with the below, you should consider doing a full assessment.

#### Through reverse proxy/load balancer logs

To determine if your Grafana installation has been exploited for this vulnerability, search through your reverse proxy/load balancer access logs for instances where the path is `/dashboard/snapshot/:key`, `/api/snapshots/:key` or `/api/snapshots-delete/:deleteKey`, and the response status code was 200 (OK).
For example, if you’re using the Kubernetes ingress-nginx controller and sending logs to Loki, use a LogQL query like `{job="nginx-ingress-controller"} |= "\"status\": 200" |= "\"uri\": \"/api/snapshots/:key\""`.

#### Through the Grafana Enterprise audit feature

If you enabled “Log web requests” in your configuration with `router_logging = true`, look for
`"requestUri":"/api/snapshots-delete/”`,`“requestUri":"/api/snapshots/:key"`, or `"type":"snapshot"` in combination with `"action":"delete"`.

### Patched versions

Release 8.1.6: 

- [Download Grafana 8.1.6](https://grafana.com/grafana/download/8.1.6)
- [Release notes](https://grafana.com/docs/grafana/latest/release-notes/release-notes-8-1-6/)

Release 7.5.11: 

- [Download Grafana 7.5.11](https://grafana.com/grafana/download/7.5.11)
- [Release notes](https://grafana.com/docs/grafana/latest/release-notes/release-notes-7-5-11/)

### Solutions and mitigations

Download and install the appropriate patch for your version of Grafana.

[Grafana Cloud](https://grafana.com/cloud) instances have already been patched, and [Grafana Enterprise](https://grafana.com/products/enterprise) customers were provided with updated binaries under embargo.

### Workaround

If for some reason you cannot upgrade:

You can use a reverse proxy or similar to block access to the literal paths
* `/api/snapshots/:key`
* `/api/snapshots-delete/:deleteKey`
* `/dashboard/snapshot/:key`
* `/api/snapshots/:key`

They have no normal function and can be disabled without side effects.

### Timeline and postmortem

Here is a detailed timeline starting from when we originally learned of the issue. All times in UTC.

* 2021-09-15 14:49: Tuan Tran theblackturtle0901@gmail.com sends initial report about viewing snapshots without authentication
* 2021-09-15 15:56: Initial reproduction
* 2021-09-15 17:10: MEDIUM severity declared
* 2021-09-15 18:58: Workaround deployed on Grafana Cloud
* 2021-09-15 19:15: `/api/snapshots/:key` found to be vulnerable as well
* 2021-09-15 19:30: `/api/snapshots/:key` blocked on Grafana Cloud
* 2021-09-16 09:31: `/api/snapshots-delete/:deleteKey` found to be vulnerable as well, blocked on Grafana Cloud. From this point forward, Cloud is not affected any more.
* 2021-09-16 09:35: HIGH severity declared
* 2021-09-16 11:19: Realization that combination of deletion and viewing allows enumeration and permanent DoS
* 2021-09-16 11:19: CRITICAL declared
* 2021-09-17 10:53: Determination that no weekend work is needed. While issue is CRITICAL, scope is very limited
* 2021-09-17 14:26: Audit of Grafana Cloud concluded, no evidence of exploitation
* 2021-09-23: Grafana Cloud instances updated
* 2021-09-28 12:00: Grafana Enterprise images released to customers under embargo
* 2021-10-05 17:00: Public release

## Reporting security issues

If you think you have found a security vulnerability, please send a report to [security@grafana.com](mailto:security@grafana.com). This address can be used for all of
Grafana Labs's open source and commercial products (including but not limited to Grafana, Tempo, Loki, Amixr, k6, Tanka, and  Grafana Cloud, Grafana Enterprise, and grafana.com). We only accept vulnerability reports at this address. We would prefer that you encrypt your message to us using our PGP key. The key fingerprint is:

F988 7BEA 027A 049F AE8E  5CAA D125 8932 BE24 C5CA

The key is available from [keys.gnupg.net](http://keys.gnupg.net/pks/lookup?op=get&fingerprint=on&search=0xD1258932BE24C5CA) by searching for [security@grafana](http://keys.gnupg.net/pks/lookup?search=security@grafana&fingerprint=on&op=index.

## Security announcements

We maintain a category on the community site named [Security Announcements](https://community.grafana.com/c/security-announcements),
where we will post a summary, remediation, and mitigation details for any patch containing security fixes. You can also subscribe to email updates to this category if you have a grafana.com account and sign in to the community site, or via updates from our [Security Announcements RSS feed](https://community.grafana.com/c/security-announcements.rss).

## Acknowledgement

We would like to thank [Tran Viet Tuan](https://github.com/theblackturtle) for responsibly disclosing the initially discovered vulnerability to us.
