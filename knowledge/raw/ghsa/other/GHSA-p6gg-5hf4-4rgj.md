# Graylog vulnerable to instantiation of arbitrary classes triggered by API request

**GHSA**: GHSA-p6gg-5hf4-4rgj | **CVE**: CVE-2024-24824 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-284

**Affected Packages**:
- **org.graylog2:graylog2-server** (maven): >= 2.0.0, < 5.1.11
- **org.graylog2:graylog2-server** (maven): >= 5.2.0-alpha.1, < 5.2.4

## Description

### Summary

Arbitrary classes can be loaded and instantiated using a HTTP PUT request to the `/api/system/cluster_config/` endpoint.

### Details

Graylog's cluster config system uses fully qualified class names as config keys. To validate the existence of the requested class before using them, Graylog loads the class using the class loader. 

https://github.com/Graylog2/graylog2-server/blob/e458db8bf4f789d4d19f1b37f0263f910c8d036c/graylog2-server/src/main/java/org/graylog2/rest/resources/system/ClusterConfigResource.java#L208-L214


### PoC
A request of the following form will output the content of the `/etc/passwd` file:

```
curl -u admin:<admin-password> -X PUT http://localhost:9000/api/system/cluster_config/java.io.File \
    -H "Content-Type: application/json" \
    -H "X-Requested-By: poc" \
    -d '"/etc/passwd"'
```

To perform the request, authorization is required. Only users posessing the `clusterconfigentry:create` and `clusterconfigentry:edit` permissions are allowed to do so. These permissions are usually only granted to `Admin` users.

### Impact

If a user with the appropriate permissions performs the request, arbitrary classes with 1-arg String constructors can be instantiated. 

This will execute arbitrary code that is run during class instantiation.

In the specific use case of `java.io.File`, the behaviour of the internal web-server stack will lead to information exposure by including the entire file content in the response to the REST request.

### Credits

Analysis provided by Fabian Yamaguchi - Whirly Labs (Pty) Ltd
