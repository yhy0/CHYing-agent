# SQL Injection in Couchbase Sync Gateway

**GHSA**: GHSA-g622-r636-qfqh | **CVE**: CVE-2019-9039 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/couchbase/sync_gateway** (go): < 2.5.0

## Description

The Couchbase Sync Gateway 2.1.2 in combination with a Couchbase Server is affected by a previously undisclosed N1QL-injection vulnerability in the REST API. An attacker with access to the public REST API can insert additional N1QL statements through the parameters ?startkey? and ?endkey? of the ?_all_docs? endpoint.
