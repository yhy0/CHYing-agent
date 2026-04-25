# Searchor CLI's Search vulnerable to Arbitrary Code using Eval

**GHSA**: GHSA-66m2-493m-crh2 | **CVE**: CVE-2023-43364 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-74, CWE-94

**Affected Packages**:
- **searchor** (pip): <= 2.4.1

## Description

 An issue in Arjun Sharda's Searchor before version v.2.4.2 allows an attacker to
 execute arbitrary code via a crafted script to the eval() function in Searchor's src/searchor/main.py file, affecting the search feature in Searchor's CLI (Command Line Interface).

### Impact
Versions equal to, or below 2.4.1 are affected.

### Patches
Versions above, or equal to 2.4.2 have patched the vulnerability.

### References
https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection
https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-
https://github.com/jonnyzar/POC-Searchor-2.4.2
https://github.com/ArjunSharda/Searchor/pull/130
