# Apache Pulsar: Pulsar Functions Worker's Archive Extraction Vulnerability Allows Unauthorized File Modification

**GHSA**: GHSA-jg2g-4rjg-cmqh | **CVE**: CVE-2024-27317 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-22

**Affected Packages**:
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 2.4.0, < 2.10.6
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 2.11.0, < 2.11.4
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 3.0.0, < 3.0.3
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 3.1.0, < 3.1.3
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 3.2.0, < 3.2.1

## Description

In Pulsar Functions Worker, authenticated users can upload functions in jar or nar files. These files, essentially zip files, are extracted by the Functions Worker. However, if a malicious file is uploaded, it could exploit a directory traversal vulnerability. This occurs when the filenames in the zip files, which aren't properly validated, contain special elements like "..", altering the directory path. This could allow an attacker to create or modify files outside of the designated extraction directory, potentially influencing system behavior. This vulnerability also applies to the Pulsar Broker when it is configured with "functionsWorkerEnabled=true".

This issue affects Apache Pulsar versions from 2.4.0 to 2.10.5, from 2.11.0 to 2.11.3, from 3.0.0 to 3.0.2, from 3.1.0 to 3.1.2, and 3.2.0. 

2.10 Pulsar Function Worker users should upgrade to at least 2.10.6.
2.11 Pulsar Function Worker users should upgrade to at least 2.11.4.
3.0 Pulsar Function Worker users should upgrade to at least 3.0.3.
3.1 Pulsar Function Worker users should upgrade to at least 3.1.3.
3.2 Pulsar Function Worker users should upgrade to at least 3.2.1.

Users operating versions prior to those listed above should upgrade to the aforementioned patched versions or newer versions.
