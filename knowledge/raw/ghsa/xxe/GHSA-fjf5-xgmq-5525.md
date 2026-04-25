# GeoServer is vulnerable to Unauthenticated XML External Entities (XXE) attack via WMS GetMap feature

**GHSA**: GHSA-fjf5-xgmq-5525 | **CVE**: CVE-2025-58360 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-611

**Affected Packages**:
- **org.geoserver.web:gs-web-app** (maven): >= 2.26.0, < 2.26.2
- **org.geoserver:gs-wms** (maven): >= 2.26.0, < 2.26.2
- **org.geoserver.web:gs-web-app** (maven): < 2.25.6
- **org.geoserver:gs-wms** (maven): < 2.25.6

## Description

## Description

An XML External Entity (XXE) vulnerability was identified. The application accepts XML input through a specific endpoint ``/geoserver/wms`` operation ``GetMap``. However, this input is not sufficiently sanitized or restricted, allowing an attacker to define external entities within the XML request.

An XML External Entity attack is a type of attack that occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. This attack may lead to the disclosure of confidential data, denial of service, port scanning from the perspective of the machine where the parser is located, and other system impacts.

By exploiting this vulnerability, an attacker can:
- Read arbitrary files from the server's file system.
- Conduct Server-Side Request Forgery (SSRF) to interact with internal systems.
- Execute Denial of Service (DoS) attacks by exhausting resources.

## Resolution

Update to GeoServer 2.25.6, GeoServer 2.26.3, or GeoServer 2.27.0.

## Impact

The XXE vulnerability can be used to retrieve arbitrary files from the server's file system.

## Reference

* https://osgeo-org.atlassian.net/browse/GEOS-11682
* XBOW-024-081

## Disclaimer

This vulnerability was detected using **[XBOW](https://xbow.com/)**, a system that autonomously finds and exploits potential security vulnerabilities. The finding has been thoroughly reviewed and validated by a security researcher before submission. While XBOW is intended to work autonomously, during its development human experts ensure the accuracy and relevance of its reports.
