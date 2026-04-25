# Django vulnerable to SQL injection via _connector keyword argument in QuerySet and Q objects.

**GHSA**: GHSA-frmv-pr5f-9mcr | **CVE**: CVE-2025-64459 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-89

**Affected Packages**:
- **django** (pip): >= 5.2a1, < 5.2.8
- **django** (pip): >= 5.0a1, < 5.1.14
- **django** (pip): < 4.2.26

## Description

An issue was discovered in 5.1 before 5.1.14, 4.2 before 4.2.26, and 5.2 before 5.2.8.
The methods `QuerySet.filter()`, `QuerySet.exclude()`, and `QuerySet.get()`, and the class `Q()`, are subject to SQL injection when using a suitably crafted dictionary, with dictionary expansion, as the `_connector` argument.
Earlier, unsupported Django series (such as 5.0.x, 4.1.x, and 3.2.x) were not evaluated and may also be affected.
Django would like to thank cyberstan for reporting this issue.
