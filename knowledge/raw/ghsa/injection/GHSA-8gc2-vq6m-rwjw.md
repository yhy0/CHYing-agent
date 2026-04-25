# Amazon Redshift Python Connector vulnerable to SQL Injection

**GHSA**: GHSA-8gc2-vq6m-rwjw | **CVE**: CVE-2024-12745 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-89

**Affected Packages**:
- **redshift_connector** (pip): = 2.1.4

## Description

### Summary
A SQL injection in the Amazon Redshift Python Connector in version 2.1.4 allows a user to gain escalated privileges via schema injection in the get_schemas, get_tables, or get_columns Metadata APIs. Users should upgrade to the driver version 2.1.5 or revert to driver version 2.1.3.

### Impact
A SQL injection is possible in the Amazon Redshift Python Connector, version 2.1.4, when leveraging metadata APIs to retrieve information about database schemas, tables, or columns.

**Impacted versions:** Amazon Redshift Python Connector version 2.1.4.

### Patches
The issue described above has been addressed in the Amazon Redshift Python Connector, version 2.1.5. 

The patch implemented in this version ensures that every metadata command input is sent to the Redshift server as part of a parameterized query, using either QUOTE_IDENT(string) or QUOTE_LITERAL(string). After processing all the inputs into quoted identifiers or literals, the metadata command is composed using these inputs and then executed on the server.

### Workarounds
Use the previous version of the Amazon Redshift Python Connector, version 2.1.3.

### References
If you have any questions or comments about this advisory we ask that you contact AWS/Amazon Security via our vulnerability reporting page [1] or directly via email to [aws-security@amazon.com](mailto:aws-security@amazon.com). Please do not create a public GitHub issue.

[1] Vulnerability reporting page: https://aws.amazon.com/security/vulnerability-reporting
