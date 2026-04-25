# changedetection.io Vulnerable to Improper Input Validation Leading to LFR/Path Traversal

**GHSA**: GHSA-j5vv-6wjg-cfr8 | **CVE**: CVE-2024-56509 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-22, CWE-200

**Affected Packages**:
- **changedetection.io** (pip): < 0.48.05

## Description

### Summary
Improper input validation in the application can allow attackers to perform local file read (LFR) or path traversal attacks. These vulnerabilities occur when user input is used to construct file paths without adequate sanitization or validation. For example, using `file:../../../etc/passwd` or `file: ///etc/passwd` can bypass weak validations and allow unauthorized access to sensitive files. Even though this has been addressed in previous patch, it is still insufficient.

### Details
The check in this line of code is insufficient.
```
if re.search(r'^file:/', url.strip(), re.IGNORECASE):
```
The attacker can still bypass this by using:
-`file:../../../../etc/passwd`
-`file: ///etc/passwd` (with space before /)

### PoC
- Open up a changedetection.io instance with a webdriver configured.
- Create a new watch with `file:../../../../etc/passwd`.
- Check the watch preview.
- The contents of `/etc/passwd` should pop out.

### Screenshots
![image](https://github.com/user-attachments/assets/55c34f2e-cafb-4a7a-a7ef-ec222e3f519b)
![image](https://github.com/user-attachments/assets/d41189f5-7bf2-48b5-9ce3-c26f79cefeda)
