#  HashiCorp Terraform Amazon Web Services (AWS) uses an insecure PRNG 

**GHSA**: GHSA-r48h-jr2j-9g78 | **CVE**: CVE-2018-9057 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-332

**Affected Packages**:
- **github.com/hashicorp/terraform-provider-aws** (go): < 1.14.0

## Description

aws/resource_aws_iam_user_login_profile.go in the HashiCorp Terraform Amazon Web Services (AWS) provider through v1.12.0 has an inappropriate PRNG algorithm and seeding, which makes it easier for remote attackers to obtain access by leveraging an IAM account that was provisioned with a weak password.
