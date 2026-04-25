# NLTK has a Zip Slip Vulnerability

**GHSA**: GHSA-7p94-766c-hgjp | **CVE**: CVE-2025-14009 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-94

**Affected Packages**:
- **nltk** (pip): <= 3.9.2

## Description

A critical vulnerability exists in the NLTK downloader component of nltk/nltk, affecting all versions. The _unzip_iter function in nltk/downloader.py uses zipfile.extractall() without performing path validation or security checks. This allows attackers to craft malicious zip packages that, when downloaded and extracted by NLTK, can execute arbitrary code. The vulnerability arises because NLTK assumes all downloaded packages are trusted and extracts them without validation. If a malicious package contains Python files, such as __init__.py, these files are executed automatically upon import, leading to remote code execution. This issue can result in full system compromise, including file system access, network access, and potential persistence mechanisms.
