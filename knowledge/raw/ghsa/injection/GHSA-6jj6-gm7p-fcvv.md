# Remote Code Execution (RCE) vulnerability in geoserver

**GHSA**: GHSA-6jj6-gm7p-fcvv | **CVE**: CVE-2024-36401 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **org.geoserver.web:gs-web-app** (maven): >= 2.24.0, < 2.24.4
- **org.geoserver:gs-wfs** (maven): >= 2.24.0, < 2.24.4
- **org.geoserver:gs-wms** (maven): >= 2.24.0, < 2.24.4
- **org.geoserver.web:gs-web-app** (maven): >= 2.25.0, < 2.25.2
- **org.geoserver:gs-wfs** (maven): >= 2.25.0, < 2.25.2
- **org.geoserver:gs-wms** (maven): >= 2.25.0, < 2.25.2
- **org.geoserver.web:gs-web-app** (maven): >= 2.23.0, < 2.23.6
- **org.geoserver:gs-wfs** (maven): >= 2.23.0, < 2.23.6
- **org.geoserver:gs-wms** (maven): >= 2.23.0, < 2.23.6
- **org.geoserver.web:gs-web-app** (maven): < 2.22.6
- **org.geoserver:gs-wfs** (maven): < 2.22.6
- **org.geoserver:gs-wms** (maven): < 2.22.6

## Description

### Summary
Multiple OGC request parameters allow Remote Code Execution (RCE) by unauthenticated users through specially crafted input against a default GeoServer installation due to unsafely evaluating property names as XPath expressions.

### Details
The GeoTools library API that GeoServer calls evaluates property/attribute names for feature types in a way that unsafely passes them to the commons-jxpath library which can execute arbitrary code when evaluating XPath expressions. This XPath evaluation is intended to be used only by complex feature types (i.e., Application Schema data stores) but is incorrectly being applied to simple feature types as well which makes this vulnerability apply to **ALL** GeoServer instances.

### PoC
No public PoC is provided but this vulnerability has been confirmed to be exploitable through WFS GetFeature, WFS GetPropertyValue, WMS GetMap, WMS GetFeatureInfo, WMS GetLegendGraphic and WPS Execute requests.

### Impact
This vulnerability can lead to executing arbitrary code.

### Workaround

A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed by an extension you are using:

Mitigation for `geoserver.war` deploy:

1. Stop the application server
2. Unzip `geoserver.war` into a directory
3. Locate the file `WEB-INF/lib/gt-complex-x.y.jar` and remove
4. Zip the directory into a new `geoserver.war`
5. Restart the application server

Mitigation for GeoServer binary:

1. Stop Jetty
2. Locate the file `webapps/geoserver/WEB-INF/lib/gt-complex-x.y.jar` and remove
3. Restart Jetty

The following extensions and community modules are known to have a direct dependency on `gt-complex` jar and are not expected function properly without it. This is not comprehensive list and additional GeoServer functionality may be dependent on the availability of `gt-complex` jar:
* Extensions: Application Schema, Catalog Services for the Web, MongoDB Data Store
* Community Modules: Features-Templating, OGC API Modules, Smart Data Loader, SOLR Data Store

Mitigation available for prior releases patching three jars in your existing install:

1. Patched `gt-app-schema`, `gt-complex` and `gt-xsd-core` jars may be downloaded for GeoServer: [2.25.1](https://sourceforge.net/projects/geoserver/files/GeoServer/2.25.1/geoserver-2.25.1-patches.zip/download), [2.24.3](https://sourceforge.net/projects/geoserver/files/GeoServer/2.24.3/geoserver-2.24.3-patches.zip/download), [2.24.2](https://sourceforge.net/projects/geoserver/files/GeoServer/2.24.2/geoserver-2.24.2-patches.zip/download), [2.23.2](https://sourceforge.net/projects/geoserver/files/GeoServer/2.23.2/geoserver-2.23.2-patches.zip/download), [2.22.2](https://sourceforge.net/projects/geoserver/files/GeoServer/2.22.2/geoserver-2.22.2-patches.zip/download), [2.21.5](https://sourceforge.net/projects/geoserver/files/GeoServer/2.21.5/geoserver-2.21.5-patches.zip/download), [2.21.4](https://sourceforge.net/projects/geoserver/files/GeoServer/2.21.4/geoserver-2.21.4-patches.zip/download),[2.20.7](https://sourceforge.net/projects/geoserver/files/GeoServer/2.20.7/geoserver-2.20.7-patches.zip/download), [2.20.4](https://sourceforge.net/projects/geoserver/files/GeoServer/2.20.4/geoserver-2.20.4-patches.zip/download), [2.19.2](https://sourceforge.net/projects/geoserver/files/GeoServer/2.19.2/geoserver-2.19.2-patches.zip/download), [2.18.0](https://sourceforge.net/projects/geoserver/files/GeoServer/2.18.0/geoserver-2.18.0-patches.zip/download).
  
   As example the 2.25.1 page links to [geoserver-2.25.1-patches.zip](https://sourceforge.net/projects/geoserver/files/GeoServer/2.25.1/geoserver-2.25.1-patches.zip/download) download on source forge.

2. Unzip the `geoserver-x.y.z-patches.zip` which contains three jars that have been patched to configure `commons-jxpath` with an empty function list prior to use. These files are drop-in replacements with identical file names to those they are replacing.

3. Follow the instructions above to locate `WEB-INF/lib` folder and replace the existing `gt-app-schema`, `gt-complex` and `gt-xsd-core` jars with those supplied by the patch.

### References
https://github.com/geotools/geotools/security/advisories/GHSA-w3pj-wh35-fq8w
https://osgeo-org.atlassian.net/browse/GEOT-7587
https://github.com/geotools/geotools/pull/4797
https://github.com/Warxim/CVE-2022-41852?tab=readme-ov-file#workaround-for-cve-2022-41852
