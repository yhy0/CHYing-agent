# ansibleguy-webui Cross-site Scripting vulnerability

**GHSA**: GHSA-927p-xrc2-x2gj | **CVE**: CVE-2024-36110 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-79

**Affected Packages**:
- **ansibleguy-webui** (pip): < 0.0.21

## Description

### Impact
Multiple forms in version <0.0.21 allowed injection of HTML elements.
These are returned to the user after executing job actions and thus evaluated by the browser.

### Patches
We recommend to upgrade to version >= [0.0.21](https://github.com/ansibleguy/webui/releases/tag/0.0.21)

### References

* [Report](https://github.com/ansibleguy/webui/files/15358522/Report.pdf)
* [GitHub Issue 44](https://github.com/ansibleguy/webui/issues/44)

