# [XBOW-025-068] XML External Entity (XXE) Processing Vulnerability in GeoServer WFS Service

**GHSA**: GHSA-jj54-8f66-c5pc | **CVE**: CVE-2025-30220 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-611, CWE-918

**Affected Packages**:
- **org.geoserver.web:gs-web-app** (maven): = 2.27.0
- **org.geoserver:gs-wfs** (maven): = 2.27.0
- **org.geoserver.web:gs-web-app** (maven): >= 2.26.0, <= 2.26.2
- **org.geoserver:gs-wfs** (maven): >= 2.26.0, <= 2.26.2
- **org.geoserver.web:gs-web-app** (maven): <= 2.25.6
- **org.geoserver:gs-wfs** (maven): <= 2.25.6

## Description

## Summary

GeoServer Web Feature Service (WFS) web service was found to be vulnerable to GeoTools CVE-2025-30220 XML External Entity (XXE) processing attack.

It is possible to trigger the parsing of external DTDs and entities, bypassing standard entity resolvers.  This allows for Out-of-Band (OOB) data exfiltration of local files accessible by the GeoServer process, and Service Side Request Forgery (SSRF).

## Details

While direct entity resolution is managed by application property ENTITY_RESOLUTION_ALLOWLIST for XML Parsing, this restriction was not being used by the GeoTools library when building an in-memory XSD Library Schema representation.

This bypasses GeoServer's AllowListEntityResolver enabling XXE attacks.

## PoC

No public PoC is provided but this vulnerability has been confirmed to be exploitable through WFS service.

## Impact

* Information Disclosure: 

  This vulnerability allows unauthenticated attackers to read arbitrary files from the server's filesystem that are accessible to the GeoServer process.
  
  This can lead to exposure of sensitive information including configuration files, credentials, and system files. The attack can be performed remotely without authentication, making it particularly severe.

* Server-Side Request Forgery (SSRF) 
  
  The mechanism inherently allows forcing GeoServer to make HTTP requests to arbitrary URLs, enabling SSRF attacks against internal network resources 

## References

* [CVE-2025-30220](https://github.com/geotools/geotools/security/advisories/GHSA-826p-4gcg-35vw) XML External Entity (XXE) Processing Vulnerability in XSD schema handling
* [External Entities Resolution](https://docs.geoserver.org/latest/en/user/production/config.html#production-config-external-entities) (GeoServer User Manual)

## Acknowledgements

This vulnerability was initially reported via an automated tool described below. Subsequently a duplicate report via @YacineF, and their patience working with the GeoServer project, was instrumental finding in escalating this issue and determining a resolution.

### XBOW-025-068 Disclaimer

This vulnerability was detected using **[XBOW](https://xbow.com/)**, a system that autonomously finds and exploits potential security vulnerabilities. The finding has been thoroughly reviewed and validated by a security researcher before submission. While XBOW is intended to work autonomously, during its development human experts ensure the accuracy and relevance of its reports.
