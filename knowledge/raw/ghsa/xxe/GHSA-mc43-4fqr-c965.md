# GeoServer has improper ENTITY_RESOLUTION_ALLOWLIST URI validation in XML Processing (SSRF)

**GHSA**: GHSA-mc43-4fqr-c965 | **CVE**: CVE-2024-34711 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-20, CWE-200, CWE-611, CWE-918

**Affected Packages**:
- **org.geoserver.web:gs-web-app** (maven): < 2.25.0
- **org.geoserver.main:gs-main** (maven): < 2.25.0

## Description

### Summary
An improper URI validation vulnerability exists that enables an unauthorized attacker to perform XML External Entities (XEE) attack, then send GET request to any HTTP server. Attacker can abuse this to scan internal networks and gain information about them then exploit further. Moreover, attacker can read limited `.xsd` file on system.

### Details
By default, GeoServer use `PreventLocalEntityResolver` class from GeoTools to filter out malicious URIs in XML entities before resolving them. The URI must match the regex `(?i)(jar:file|http|vfs)[^?#;]*\\.xsd`. But the regex leaves a chance for attackers to request to any HTTP server or limited file.

### Impact

An unauthenticated attacker can:
1. Scan internal network to gain insight about it and exploit further.
2. SSRF to endpoint ends with `.xsd`.
3. Read limited `.xsd` file on system.

### Mitigation

1. Define the system property ``ENTITY_RESOLUTION_ALLOWLIST`` to limit the supported external schema locaitons.
2. The built-in allow list covers the locations required for the operation of OGC web services: ``www.w3.org``,``schemas.opengis.net``,``www.opengis.net``,``inspire.ec.europa.eu/schemas``.
3. The [user guide](https://docs.geoserver.org/latest/en/user/production/config.html#production-config-external-entities) provides details on how to add additional locations (this is required for app-schema plugin where a schema is supplied to define an output format).

### Resolution 

1. GeoServer 2.25.0 and greater default to the use of ``ENTITY_RESOLUTION_ALLOWLIST`` and does not require you to provide a system property.
2. The use of ``ENTITY_RESOLUTION_ALLOWLIST`` is still supported if you require additional schema locations to be supported beyond the built-in allow list.
3. GeoServer 2.25.1 change ``ENTITY_RESOLUTION_ALLOWLIST `` no longer supports regular expressions

### References

* [External Entities Resolution](https://docs.geoserver.org/latest/en/user/production/config.html#production-config-external-entities) (GeoServer User Guide)

### Credits
* Le Mau Anh Phong from VNG Security Response Center & VNUHCM - University of Information Technology
