# GeoTools Remote Code Execution (RCE) vulnerability in evaluating XPath expressions

**GHSA**: GHSA-w3pj-wh35-fq8w | **CVE**: CVE-2024-36404 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-95

**Affected Packages**:
- **org.geotools:gt-app-schema** (maven): >= 30.0, < 30.4
- **org.geotools:gt-complex** (maven): >= 30.0, < 30.4
- **org.geotools.xsd:gt-xsd-core** (maven): >= 30.0, < 30.4
- **org.geotools:gt-app-schema** (maven): >= 31.0, < 31.2
- **org.geotools:gt-complex** (maven): >= 31.0, < 31.2
- **org.geotools.xsd:gt-xsd-core** (maven): >= 31.0, < 31.2
- **org.geotools:gt-app-schema** (maven): >= 29.0, < 29.6
- **org.geotools:gt-complex** (maven): >= 29.0, < 29.6
- **org.geotools.xsd:gt-xsd-core** (maven): >= 29.0, < 29.6
- **org.geotools:gt-app-schema** (maven): < 28.6
- **org.geotools:gt-complex** (maven): < 28.6
- **org.geotools.xsd:gt-xsd-core** (maven): < 28.6

## Description

### Summary
Remote Code Execution (RCE) is possible if an application uses certain GeoTools functionality to evaluate XPath expressions supplied by user input.

### Details
The following methods pass XPath expressions to the `commons-jxpath` library which can execute arbitrary code and would be a security issue if the XPath expressions are provided by user input.

* `org.geotools.appschema.util.XmlXpathUtilites.getXPathValues(NamespaceSupport, String, Document)`
* `org.geotools.appschema.util.XmlXpathUtilites.countXPathNodes(NamespaceSupport, String, Document)`
* `org.geotools.appschema.util.XmlXpathUtilites.getSingleXPathValue(NamespaceSupport, String, Document)`
* `org.geotools.data.complex.expression.FeaturePropertyAccessorFactory.FeaturePropertyAccessor.get(Object, String, Class<T>)`
* `org.geotools.data.complex.expression.FeaturePropertyAccessorFactory.FeaturePropertyAccessor.set(Object, String, Object, Class)`
* `org.geotools.data.complex.expression.MapPropertyAccessorFactory.new PropertyAccessor() {...}.get(Object, String, Class<T>)`
* `org.geotools.xsd.StreamingParser.StreamingParser(Configuration, InputStream, String)`

### PoC
The following inputs to StreamingParser will delay the response by five seconds:
```
        new org.geotools.xsd.StreamingParser(
                        new org.geotools.filter.v1_0.OGCConfiguration(),
                        new java.io.ByteArrayInputStream("<Filter></Filter>".getBytes()),
                        "java.lang.Thread.sleep(5000)")
                .parse();
```

### Impact

This vulnerability can lead to executing arbitrary code.

### Mitigation

GeoTools can operate with reduced functionality by removing the `gt-complex` jar from your application.  As an example of the impact application schema datastore would not function without the ability to use XPath expressions to query complex content.

The SourceForge download page lists drop-in-replacement jars for GeoTools: [31.1](https://sourceforge.net/projects/geotools/files/GeoTools%2031%20Releases/31.1/), [30.3](https://sourceforge.net/projects/geotools/files/GeoTools%2030%20Releases/30.3/geotools-30.3-patches.zip/download), [30.2](https://sourceforge.net/projects/geotools/files/GeoTools%2030%20Releases/30.2/geotools-30.2-patches.zip/download), [29.2](https://sourceforge.net/projects/geotools/files/GeoTools%2029%20Releases/29.2/geotools-29.2-patches.zip/download), [28.2](https://sourceforge.net/projects/geotools/files/GeoTools%2028%20Releases/28.2/geotools-28.2-patches.zip/download), [27.5](https://sourceforge.net/projects/geotools/files/GeoTools%2027%20Releases/27.5/geotools-27.5-patches.zip/download), [27.4](https://sourceforge.net/projects/geotools/files/GeoTools%2027%20Releases/27.4/geotools-27.4-patches.zip/download), [26.7](https://sourceforge.net/projects/geotools/files/GeoTools%2026%20Releases/26.7/geotools-26.7-patches.zip/download), [26.4](https://sourceforge.net/projects/geotools/files/GeoTools%2026%20Releases/26.4/), [25.2](https://sourceforge.net/projects/geotools/files/GeoTools%2025%20Releases/25.2/geotools-25.2-patches.zip/download), [24.0](https://sourceforge.net/projects/geotools/files/GeoTools%2024%20Releases/24.0/geotools-24.0-patches.zip/download). These jars are for download only and are not available from maven central, intended to quickly provide a fix to affected applications.

### References
https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv
https://osgeo-org.atlassian.net/browse/GEOT-7587
https://github.com/geotools/geotools/pull/4797
https://github.com/Warxim/CVE-2022-41852?tab=readme-ov-file#workaround-for-cve-2022-41852
