# GeoTools has XML External Entity (XXE) Processing Vulnerability in XSD schema handling

**GHSA**: GHSA-826p-4gcg-35vw | **CVE**: N/A | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-611

**Affected Packages**:
- **org.geotools:gt-xsd-core** (maven): = 33.0
- **org.geotools:gt-xsd-core** (maven): >= 32.0, < 32.3
- **org.geotools:gt-xsd-core** (maven): >= 29.0, <= 31.6
- **org.geotools:gt-wfs-ng** (maven): >= 33.0, < 33.1
- **org.geotools:gt-wfs-ng** (maven): >= 32.0, < 32.3
- **org.geotools:gt-wfs-ng** (maven): >= 29.0, <= 31.6
- **org.geotools:gt-xsd-core** (maven): < 28.6.1
- **org.geotools:gt-wfs-ng** (maven): < 28.6.1

## Description

### Summary

GeoTools Schema class use of Eclipse XSD library to represent schema data structure is vulnerable to XML External Entity (XXE) exploit.

### Impact

This impacts whoever exposes XML processing with ``gt-xsd-core`` involved in parsing, when the documents carry a reference to an external XML schema. The ``gt-xsd-core`` Schemas class is not using the EntityResolver provided by the ParserHandler (if any was configured).

This also impacts users of ``gt-wfs-ng`` DataStore where the ENTITY_RESOLVER connection parameter was not being used as intended.

### Resolution

GeoTools API change allows EntityResolver to be supplied to the following methods:

```java
Schemas.parse( location, locators, resolvers, uriHandlers, entityResolver);
Schemas.findSchemas(Configuration configuration, EntityResolver entityResolver);
```

With this API change the `gt-wfs-ng` WFS DataStore ENTITY_RESOLVER parameter is now used.

### Reference

* [GHSA-jj54-8f66-c5pc](https://github.com/geoserver/geoserver/security/advisories/GHSA-jj54-8f66-c5pc): Describes the impact of the ``gt-xsd-core`` vulnerability on the GeoServer WFS protocol, resulting in both Service Side Request Forgery (SSRF) and Out-of-Band (OOB) data exfiltration of local files.

* [GHSA-2p76-gc46-5fvc](https://github.com/geonetwork/core-geonetwork/security/advisories/GHSA-2p76-gc46-5fvc): Describes the impact of the ``gt-wfs-ng`` and ``gt-xsd-core`` vulnerability on the GeoNetwork WFS Index functionality.
