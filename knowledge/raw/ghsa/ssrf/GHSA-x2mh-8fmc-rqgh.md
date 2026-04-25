# Apache Airflow denial of service vulnerability

**GHSA**: GHSA-x2mh-8fmc-rqgh | **CVE**: CVE-2023-37379 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-200, CWE-400, CWE-918

**Affected Packages**:
- **apache-airflow** (pip): < 2.7.0b1

## Description

Apache Airflow, in versions prior to 2.7.0, contains a security vulnerability that can be exploited by an authenticated user possessing Connection edit privileges. This vulnerability allows the user to access connection information and exploit the test connection feature by sending many requests, leading to a denial of service (DoS) condition on the server. Furthermore, malicious actors can leverage this vulnerability to establish harmful connections with the server.

Users of Apache Airflow are strongly advised to upgrade to version 2.7.0 or newer to mitigate the risk associated with this vulnerability. Additionally, administrators are encouraged to review and adjust user permissions to restrict access to sensitive functionalities, reducing the attack surface.
