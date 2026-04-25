# AWS Advanced Python Wrapper: Privilege Escalation in Aurora PostgreSQL instance 

**GHSA**: GHSA-4jvf-wx3f-2x8q | **CVE**: CVE-2025-12967 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-470

**Affected Packages**:
- **aws_advanced_python_wrapper** (pip): < 1.4.0

## Description

### Description of Vulnerability:

An issue in AWS Wrappers for Amazon Aurora PostgreSQL may allow for privilege escalation to rds_superuser role. A low privilege authenticated user can create a crafted function that could be executed with permissions of other Amazon Relational Database Service (RDS) users.

AWS recommends customers upgrade to the following versions:  AWS Python Wrapper to v1.4.0


### Source of Vulnerability Report: 
Allistair Ishmael Hakim <allistair.hakim@gmail.com>


### Affected products & versions: 
AWS Python Wrapper < 1.4.0


### Platforms: 
MacOS/Windows/Linux
