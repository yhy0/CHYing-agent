# Grafana path traversal

**GHSA**: GHSA-8pjx-jj86-j47p | **CVE**: CVE-2021-43798 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/grafana/grafana** (go): >= 8.3.0, < 8.3.1
- **github.com/grafana/grafana** (go): >= 8.2.0, < 8.2.7
- **github.com/grafana/grafana** (go): >= 8.1.0, < 8.1.8
- **github.com/grafana/grafana** (go): >= 8.0.0-beta1, < 8.0.7

## Description

Today we are releasing Grafana 8.3.1, 8.2.7, 8.1.8, 8.0.7. This patch release includes a high severity security fix that affects Grafana versions from v8.0.0-beta1 through v8.3.0.

Release v8.3.1, only containing a security fix:

- [Download Grafana 8.3.1](https://grafana.com/grafana/download/8.3.1)
- [Release notes](https://grafana.com/docs/grafana/latest/release-notes/release-notes-8-3-1/)

Release v8.2.7, only containing a security fix:

- [Download Grafana 8.2.7](https://grafana.com/grafana/download/8.2.7)
- [Release notes](https://grafana.com/docs/grafana/latest/release-notes/release-notes-8-2-7/)

Release v8.1.8, only containing a security fix:

- [Download Grafana 8.1.8](https://grafana.com/grafana/download/8.1.8)
- [Release notes](https://grafana.com/docs/grafana/latest/release-notes/release-notes-8-1-8/)

Release v8.0.7, only containing a security fix:

- [Download Grafana 8.0.7](https://grafana.com/grafana/download/8.0.7)
- [Release notes](https://grafana.com/docs/grafana/latest/release-notes/release-notes-8-0-7/)


## Path Traversal ([CVE-2021-43798](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43798))

### Summary 

On 2021-12-03, we received a report that Grafana is vulnerable to directory traversal, allowing access to local files. We have confirmed this for versions 8.0.0-beta1 to 8.3.0. Thanks to our defense-in-depth approach, at no time has [Grafana Cloud](https://grafana.com/cloud) been vulnerable.

The vulnerable URL path is: <grafana_host_url>/public/plugins/<plugin-id>/, where <plugin-id> is the plugin ID for any installed plugin.

Every Grafana instance comes with pre-installed plugins like the Prometheus plugin or MySQL plugin so the following URLs are vulnerable for every instance:

* <grafana_host_url>/public/plugins/alertlist/
* <grafana_host_url>/public/plugins/annolist/
* <grafana_host_url>/public/plugins/barchart/
* <grafana_host_url>/public/plugins/bargauge/
* <grafana_host_url>/public/plugins/candlestick/
* <grafana_host_url>/public/plugins/cloudwatch/
* <grafana_host_url>/public/plugins/dashlist/
* <grafana_host_url>/public/plugins/elasticsearch/
* <grafana_host_url>/public/plugins/gauge/
* <grafana_host_url>/public/plugins/geomap/
* <grafana_host_url>/public/plugins/gettingstarted/
* <grafana_host_url>/public/plugins/grafana-azure-monitor-datasource/
* <grafana_host_url>/public/plugins/graph/
* <grafana_host_url>/public/plugins/heatmap/
* <grafana_host_url>/public/plugins/histogram/
* <grafana_host_url>/public/plugins/influxdb/
* <grafana_host_url>/public/plugins/jaeger/
* <grafana_host_url>/public/plugins/logs/
* <grafana_host_url>/public/plugins/loki/
* <grafana_host_url>/public/plugins/mssql/
* <grafana_host_url>/public/plugins/mysql/
* <grafana_host_url>/public/plugins/news/
* <grafana_host_url>/public/plugins/nodeGraph/
* <grafana_host_url>/public/plugins/opentsdb
* <grafana_host_url>/public/plugins/piechart/
* <grafana_host_url>/public/plugins/pluginlist/
* <grafana_host_url>/public/plugins/postgres/
* <grafana_host_url>/public/plugins/prometheus/
* <grafana_host_url>/public/plugins/stackdriver/
* <grafana_host_url>/public/plugins/stat/
* <grafana_host_url>/public/plugins/state-timeline/
* <grafana_host_url>/public/plugins/status-history/
* <grafana_host_url>/public/plugins/table/
* <grafana_host_url>/public/plugins/table-old/
* <grafana_host_url>/public/plugins/tempo/
* <grafana_host_url>/public/plugins/testdata/
* <grafana_host_url>/public/plugins/text/
* <grafana_host_url>/public/plugins/timeseries/
* <grafana_host_url>/public/plugins/welcome/
* <grafana_host_url>/public/plugins/zipkin/

We have received CVE-2021-43798 for this issue. The CVSS score for this vulnerability is 7.5 High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) for Grafana versions 8.0.0-beta1 to 8.3.0 

### Affected versions with high severity 

Grafana 8.0.0-beta1 to 8.3.0

### Solutions and mitigations

All installations between v8.0.0-beta1 and v8.3.0 should be upgraded as soon as possible.

If you can not upgrade, running a reverse proxy in front of Grafana that normalizes the PATH of the request will mitigate the vulnerability. For example the normalize_path setting in envoy.

Thanks to our defense-in-depth approach, [Grafana Cloud](https://grafana.com/cloud) instances have not been affected by the vulnerability.

As always, we closely coordinated with all cloud providers licensed to offer Grafana Pro. They have received early notification under embargo and confirmed that their offerings are secure at the time of this announcement. In alphabetical order, this is applicable to Amazon Managed Grafana, and Azure Managed Grafana.

### Timeline and postmortem

Here is a detailed timeline starting from when we originally learned of the issue. All times in UTC.

* 2021-12-03: Security researcher sends the initial report
* 2021-12-03: Confirmed for 8.0.0-beta1 through 8.3.0
* 2021-12-03: Confirmed that Grafana Cloud is not vulnerable
* 2021-12-03: Security fix determined and committed to Git
* 2021-12-03: Release timeline determined: 2021-12-07 for private customer release, 2021-12-14 for public release
* 2021-12-06: Second report about the vulnerability received
* 2021-12-07: We received information that the vulnerability has been leaked to the public, turning it into a 0 day
* 2021-12-07: Decision made to release as quickly as feasible
* 2021-12-07: Private release with reduced two hour grace period instead of the usual 1 week
* 2021-12-07: Public release

### Acknowledgements

We would like to thank [Jordy Versmissen](https://twitter.com/j0v0x0) for finding the vulnerability and alerting us to it.

## Reporting security Issues

If you think you have found a security vulnerability, please send a report to [security@grafana.com](mailto:security@grafana.com). This address can be used for all of
Grafana Labs' open source and commercial products (including but not limited to Grafana, Grafana Cloud, Grafana Enterprise, and grafana.com). We can accept only vulnerability reports at this address. We would prefer that you encrypt your message to us by using our PGP key. The key fingerprint is

F988 7BEA 027A 049F AE8E  5CAA D125 8932 BE24 C5CA

The key is available from [keyserver.ubuntu.com](https://keyserver.ubuntu.com/pks/lookup?search=0xF9887BEA027A049FAE8E5CAAD1258932BE24C5CA&fingerprint=on&op=index).

## Security announcements

We maintain a [security category on our blog](https://grafana.com/tags/security/), where we will always post a summary, remediation, and mitigation details for any patch containing security fixes. 

You can also subscribe to our [RSS feed](https://grafana.com/tags/security/index.xml).
