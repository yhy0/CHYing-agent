# Apache Solr: Backup/Restore APIs allow for  deployment of executables in malicious ConfigSets 

**GHSA**: GHSA-37vr-vmg4-jwpw | **CVE**: CVE-2023-50386 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-434

**Affected Packages**:
- **org.apache.solr:solr-core** (maven): >= 6.0.0, < 8.11.3
- **org.apache.solr:solr-core** (maven): >= 9.0.0, < 9.4.1

## Description

Improper Control of Dynamically-Managed Code Resources, Unrestricted Upload of File with Dangerous Type, Inclusion of Functionality from Untrusted Control Sphere vulnerability in Apache Solr.This issue affects Apache Solr from 6.0.0 through 8.11.2, from 9.0.0 before 9.4.1.

In the affected versions, Solr ConfigSets accepted Java jar and class files to be uploaded through the ConfigSets API.
When backing up Solr Collections, these configSet files would be saved to disk when using the LocalFileSystemRepository (the default for backups).
If the backup was saved to a directory that Solr uses in its ClassPath/ClassLoaders, then the jar and class files would be available to use with any ConfigSet, trusted or untrusted.

When Solr is run in a secure way (Authorization enabled), as is strongly suggested, this vulnerability is limited to extending the Backup permissions with the ability to add libraries.
Users are recommended to upgrade to version 8.11.3 or 9.4.1, which fix the issue.
In these versions, the following protections have been added:

  *  Users are no longer able to upload files to a configSet that could be executed via a Java ClassLoader.
  *  The Backup API restricts saving backups to directories that are used in the ClassLoader.
