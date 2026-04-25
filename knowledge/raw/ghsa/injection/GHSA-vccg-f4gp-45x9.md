# Eval Injection in fastbots

**GHSA**: GHSA-vccg-f4gp-45x9 | **CVE**: CVE-2023-48699 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-94, CWE-95

**Affected Packages**:
- **fastbots** (pip): < 0.1.5

## Description

### Impact
An attacker could modify the locators.ini locator file with python code that without proper validation it's executed and it could lead to rce. The vulnerability is in the function def __locator__(self, locator_name: str) in page.py. The vulnerable code that load and execute directly from the file without validation it's:
```python
 return eval(self._bot.locator(self._page_name, locator_name))
```

### Patches
In order to mitigate this issue it's important to upgrade to fastbots version 0.1.5 or above. 

### References
[Merge that fix also this issue](https://github.com/ubertidavide/fastbots/pull/3#issue-2003080806)
