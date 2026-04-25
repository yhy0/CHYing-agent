# Sandbox escape via various forms of "format".

**GHSA**: GHSA-xjw2-6jm9-rf67 | **CVE**: CVE-2023-41039 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-74

**Affected Packages**:
- **RestrictedPython** (pip): <= 5.3
- **RestrictedPython** (pip): >= 6.0, <= 6.1

## Description

### Impact
Python's "format" functionality allows someone controlling the format string to "read" all objects accessible through recursive attribute lookup and subscription from objects he can access. This can lead to critical information disclosure.
With `RestrictedPython`, the format functionality is available via the `format` and `format_map` methods of `str` (and `unicode`) (accessed either via the class or its instances) and via `string.Formatter`.
All known versions of `RestrictedPython` are vulnerable. 

### Patches
The issue will be fixed in 5.4 and 6.2.

### Workarounds
There are no workarounds to fix the issue without upgrading.

### References
* https://docs.python.org/3/library/stdtypes.html#str.format_map
* http://lucumr.pocoo.org/2016/12/29/careful-with-str-format/
* https://www.exploit-db.com/exploits/51580

### For more information

If you have any questions or comments about this advisory:

* Open an issue in the [RestrictedPython issue tracker](https://github.com/zopefoundation/RestrictedPython/issues)
* Email us at [security@plone.org](mailto:security@plone.org)

### Credits

Thanks for analysing and reporting the go to:

* Abhishek Govindarasu
* Ankush Menat
* Ward Theunisse


