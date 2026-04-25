# MindsDB can be made to not verify SSL certificates

**GHSA**: GHSA-8hx6-qv6f-xgcw | **CVE**: CVE-2023-38699 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-311

**Affected Packages**:
- **MindsDB** (pip): < 23.7.4.0

## Description

### Summary
MindsDB's AI Virtual Database allows developers to connect any AI/ML model to any datasource. Prior to version 23.7.4.0, a call to requests with `verify=False` disables SSL certificate checks. This rule enforces always verifying SSL certificates for methods in the Requests library. In version 23.7.4.0, certificates are validated by default, which is the desired behavior

Encryption in general is typically critical to the security of many applications. Using TLS can significantly increase security by guaranteeing the identity of the party you are communicating with. This is accomplished by one or both parties presenting trusted certificates during the connection initialization phase of TLS.

It is important to note that modules such as httplib within the Python standard library did not verify certificate chains until it was fixed in 2.7.9 release.

### Details
Severity: Critical

