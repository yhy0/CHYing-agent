# Apache Pulsar: Pulsar Functions Worker Allows Unauthorized File Access and Unauthorized HTTP/HTTPS Proxying

**GHSA**: GHSA-c2x9-vw5h-39vc | **CVE**: CVE-2024-27894 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-20

**Affected Packages**:
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 2.4.0, < 2.10.6
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 2.11.0, < 2.11.4
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 3.0.0, < 3.0.3
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 3.1.0, < 3.1.3
- **org.apache.pulsar:pulsar-functions-worker** (maven): >= 3.2.0, < 3.2.1

## Description

The Pulsar Functions Worker includes a capability that permits authenticated users to create functions where the function's implementation is referenced by a URL. The supported URL schemes include "file", "http", and "https". When a function is created using this method, the Functions Worker will retrieve the implementation from the URL provided by the user. However, this feature introduces a vulnerability that can be exploited by an attacker to gain unauthorized access to any file that the Pulsar Functions Worker process has permissions to read. This includes reading the process environment which potentially includes sensitive information, such as secrets. Furthermore, an attacker could leverage this vulnerability to use the Pulsar Functions Worker as a proxy to access the content of remote HTTP and HTTPS endpoint URLs. This could also be used to carry out denial of service attacks.
This vulnerability also applies to the Pulsar Broker when it is configured with "functionsWorkerEnabled=true".

This issue affects Apache Pulsar versions from 2.4.0 to 2.10.5, from 2.11.0 to 2.11.3, from 3.0.0 to 3.0.2, from 3.1.0 to 3.1.2, and 3.2.0. 

2.10 Pulsar Function Worker users should upgrade to at least 2.10.6.
2.11 Pulsar Function Worker users should upgrade to at least 2.11.4.
3.0 Pulsar Function Worker users should upgrade to at least 3.0.3.
3.1 Pulsar Function Worker users should upgrade to at least 3.1.3.
3.2 Pulsar Function Worker users should upgrade to at least 3.2.1.

Users operating versions prior to those listed above should upgrade to the aforementioned patched versions or newer versions.

The updated versions of Pulsar Functions Worker will, by default, impose restrictions on the creation of functions using URLs. For users who rely on this functionality, the Function Worker configuration provides two configuration keys: "additionalEnabledConnectorUrlPatterns" and "additionalEnabledFunctionsUrlPatterns". These keys allow users to specify a set of URL patterns that are permitted, enabling the creation of functions using URLs that match the defined patterns. This approach ensures that the feature remains available to those who require it, while limiting the potential for unauthorized access and exploitation.
