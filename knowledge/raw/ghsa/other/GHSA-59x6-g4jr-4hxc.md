# GeoServer RCE due to improper control of generation of code in jai-ext`Jiffle` map algebra language

**GHSA**: GHSA-59x6-g4jr-4hxc | **CVE**: CVE-2023-35042 | **Severity**: critical (CVSS 9.8)

**CWE**: N/A

**Affected Packages**:
- **org.geoserver:gs-wms** (maven): < 2.18.6
- **org.geoserver:gs-wfs** (maven): < 2.18.6
- **org.geoserver:gs-wms** (maven): >= 2.19.0, < 2.19.6
- **org.geoserver:gs-wfs** (maven): >= 2.19.0, < 2.19.6
- **org.geoserver:gs-wms** (maven): >= 2.20.0, < 2.20.4
- **org.geoserver:gs-wfs** (maven): >= 2.20.0, < 2.20.4
- **org.geoserver:gs-wps** (maven): < 2.18.6
- **org.geoserver:gs-wps** (maven): >= 2.19.0, < 2.19.6
- **org.geoserver:gs-wps** (maven): >= 2.20.0, < 2.20.4

## Description

GeoServer 2, in some configurations, allows remote attackers to execute arbitrary code via `java.lang.Runtime.getRuntime().exec` in `wps:LiteralData` within a `wps:Execute` request, as exploited in the wild in June 2023.

## RCE in Jiffle

The Jiffle map algebra language, provided by jai-ext, allows efficiently execute map algebra over large images. A vulnerability [CVE-2022-24816](https://nvd.nist.gov/vuln/detail/CVE-2022-24816) has been recently found in Jiffle, that allows a Code Injection to be performed by properly crafting a Jiffle invocation.

In the case of GeoServer, the injection can be performed from a remote request.

## Assessment

GeoTools includes the Jiffle language as part of the `gt-process-raster-<version>` module, applications using it should check whether it’s possible to provide a Jiffle script from remote, and if so, upgrade or remove the functionality (see also the GeoServer mitigation, below).

The issue is of particular interest for GeoServer users, as GeoServer embeds Jiffle in the base WAR package. Jiffle is available as a OGC function, for usage in SLD rendering transformations.

This allows for a Remote Code Execution in properly crafted OGC requests, as well as from the administration console, when editing SLD files.

## Mitigations

In case you cannot upgrade at once, then the following mitigation is strongly recommended:

1. Stop GeoServer
2. Open the war file, get into `WEB-INF/lib` and remove the `janino-<version>.jar`
3. Restart GeoServer.

This effectively removes the Jiffle ability to compile scripts in Java code, from any of the potential attack vectors (Janino is the library used to turn the Java code generated from the Jiffle script, into executable bytecode).

GeoServer should still work properly after the removal, but any attempt to use Jiffle will result in an exception.
