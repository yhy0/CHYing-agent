# Genie Path Traversal vulnerability via File Uploads

**GHSA**: GHSA-wpcv-5jgp-69f3 | **CVE**: CVE-2024-4701 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-22

**Affected Packages**:
- **com.netflix.genie:genie-web** (maven): < 4.3.18

## Description

### Overview
Path Traversal Vulnerability via  File Uploads in Genie 

### Impact
Any Genie OSS users running their own instance and relying on the filesystem to store file attachments submitted to the Genie application may be impacted. Using this technique, it is possible to write a file with any user-specified filename and file contents to any location on the file system that the Java process has write access - potentially leading to remote code execution (RCE).

Genie users who do not store these attachments locally on the underlying file system are not vulnerable to this issue. 

### Description
Genie's API accepts a multipart/form-data file upload which can be saved to a location on disk. However, it takes a user-supplied filename as part of the request and uses this as the filename when writing the file to disk. Since this filename is user-controlled, it is possible for a malicious actor to manipulate the filename in order to break out of the default attachment storage path and perform path traversal. 

Using this technique it is possible to write a file with any user specified name and file contents to any location on the file system that the Java process has write access to.

### Patches
This path traversal issue is fixed in Genie OSS v4.3.18. This issue was fixed in https://github.com/Netflix/genie/pull/1216 and  https://github.com/Netflix/genie/pull/1217 and a [new release](https://github.com/Netflix/genie/releases/tag/v4.3.18) with the fix was created. Please, upgrade your Genie OSS instances to the new version.
