# RestrictedPython vulnerable to arbitrary code execution via stack frame sandbox escape

**GHSA**: GHSA-wqc8-x2pr-7jqh | **CVE**: CVE-2023-37271 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-913

**Affected Packages**:
- **RestrictedPython** (pip): < 5.3
- **RestrictedPython** (pip): >= 6.0a1.dev0, < 6.1
- **restrictedpython** (pip): >= 0, < 5.3

## Description

### Impact

RestrictedPython does not check access to stack frames and their attributes. Stack frames are accessible within at least generators and generator expressions, which are allowed inside RestrictedPython. An attacker with access to a RestrictedPython environment can write code that gets the current stack frame in a generator and then walk the stack all the way beyond the RestrictedPython invocation boundary, thus breaking out of the restricted scope allowing the call of unrestricted Python code and therefore potentially allowing arbitrary code execution in the Python interpreter.

All RestrictedPython deployments that allow untrusted users to write Python code in the RestrictedPython environment are at risk. In terms of Zope and Plone, this would mean deployments where the administrator allows untrusted users to create and/or edit objects of type `Script (Python)`, `DTML Method`, `DTML Document` or `Zope Page Template`. This is a non-default configuration and likely to be extremely rare.

### Patches

The problem has been fixed in releases 5.3 and 6.1.

### Workarounds

There is no workaround available. If you cannot upgrade to the latest release you should ensure the RestrictedPython environment is only available for trusted users.

### References

- [RestrictedPython security advisory GHSA-wqc8-x2pr-7jqh](https://github.com/zopefoundation/RestrictedPython/security/advisories/GHSA-wqc8-x2pr-7jqh)

## For more information

If you have any questions or comments about this advisory:

- Open an issue in the [RestrictedPython issue tracker](https://github.com/zopefoundation/RestrictedPython/issues)
- Email us at [security@plone.org](mailto:security@plone.org)

## Credits

Thanks for analysing and reporting the go to:
- Nakul Choudhary (Quasar0147 on GitHub)
- despawningbone on GitHub
- Robert Xiao (nneonneo on GitHub)
