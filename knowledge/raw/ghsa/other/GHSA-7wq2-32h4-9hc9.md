# AWS Advanced Go Wrapper: Privilege Escalation in Aurora PostgreSQL Instance

**GHSA**: GHSA-7wq2-32h4-9hc9 | **CVE**: N/A | **Severity**: high (CVSS 8.0)

**CWE**: CWE-470

**Affected Packages**:
- **github.com/aws/aws-advanced-go-wrapper/awssql** (go): < 1.1.1

## Description

### Description of Vulnerability: 
An issue in AWS Wrappers for Amazon Aurora PostgreSQL may allow for privilege escalation to rds_superuser role. A low privilege authenticated user can create a crafted function that could be executed with permissions of other Amazon Relational Database Service (RDS) users.

AWS recommends customers upgrade to the following versions:  AWS Go Wrapper to 2025-10-17.


### Source of Vulnerability Report: 
Allistair Ishmael Hakim [allistair.hakim@gmail.com](mailto:allistair.hakim@gmail.com)


### Affected products & versions: 
AWS Go Wrapper < 2025-10-17.


### Platforms:
 MacOS/Windows/Linux
