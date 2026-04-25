# Amazon Web Services Advanced JDBC Wrapper: Privilege Escalation in Aurora PostgreSQL instance

**GHSA**: GHSA-7xw4-g7mm-r4hh | **CVE**: N/A | **Severity**: high (CVSS 8.0)

**CWE**: CWE-470

**Affected Packages**:
- **software.amazon.jdbc:aws-advanced-jdbc-wrapper** (maven): <= 2.6.4

## Description

### Description of Vulnerability:
An issue in AWS Wrappers for Amazon Aurora PostgreSQL may allow for privilege escalation to rds_superuser role. A low privilege authenticated user can create a crafted function that could be executed with permissions of other Amazon Relational Database Service (RDS) users.

AWS recommends for customers to upgrade to the following versions: AWS JDBC Wrapper to v2.6.5 or greater.


### Source of Vulnerability Report: 
Allistair Ishmael Hakim [allistair.hakim@gmail.com](mailto:allistair.hakim@gmail.com)


### Affected products & versions: 
AWS JDBC Wrapper < 2.6.5

### Platforms: 
MacOS/Windows/Linux
