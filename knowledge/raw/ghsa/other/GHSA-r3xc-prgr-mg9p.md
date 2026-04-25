# Django bypasses validation when using one form field to upload multiple files

**GHSA**: GHSA-r3xc-prgr-mg9p | **CVE**: CVE-2023-31047 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-20

**Affected Packages**:
- **Django** (pip): >= 3.2a1, < 3.2.19
- **Django** (pip): >= 4.0a1, < 4.1.9
- **Django** (pip): >= 4.2a1, < 4.2.1

## Description

In Django 3.2 before 3.2.19, 4.x before 4.1.9, and 4.2 before 4.2.1, it was possible to bypass validation when using one form field to upload multiple files. This multiple upload has never been supported by forms.FileField or forms.ImageField (only the last uploaded file was validated). However, Django's "Uploading multiple files" documentation suggested otherwise.
