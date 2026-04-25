# Django SQL injection in HasKey(lhs, rhs) on Oracle

**GHSA**: GHSA-m9g8-fxxm-xg86 | **CVE**: CVE-2024-53908 | **Severity**: high (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **Django** (pip): >= 5.0.0, < 5.0.10
- **Django** (pip): >= 5.1.0, < 5.1.4
- **Django** (pip): >= 4.2.0, < 4.2.17
- **django** (pip): >= 5.1, < 5.1.4
- **django** (pip): >= 5.0, < 5.0.10
- **django** (pip): >= 4.2, < 4.2.17

## Description

An issue was discovered in Django 5.1 before 5.1.4, 5.0 before 5.0.10, and 4.2 before 4.2.17. Direct usage of the django.db.models.fields.json.HasKey lookup, when an Oracle database is used, is subject to SQL injection if untrusted data is used as an lhs value. (Applications that use the jsonfield.has_key lookup via __ are unaffected.)
