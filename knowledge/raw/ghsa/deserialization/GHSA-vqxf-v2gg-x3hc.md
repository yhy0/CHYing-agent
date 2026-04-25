# docling-core vulnerable to Remote Code Execution via unsafe PyYAML usage

**GHSA**: GHSA-vqxf-v2gg-x3hc | **CVE**: CVE-2026-24009 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-502

**Affected Packages**:
- **docling-core** (pip): >= 2.21.0, < 2.48.4

## Description

### Impact

A PyYAML-related Remote Code Execution (RCE) vulnerability, namely CVE-2020-14343, is exposed in `docling-core >=2.21.0, <2.48.4` and, specifically only if the application uses `pyyaml < 5.4` and invokes `docling_core.types.doc.DoclingDocument.load_from_yaml()` passing it untrusted YAML data.

### Patches

The vulnerability has been patched in `docling-core` version **2.48.4**.
The fix mitigates the issue by switching `PyYAML` deserialization from `yaml.FullLoader` to `yaml.SafeLoader`, ensuring that untrusted data cannot trigger code execution.

### Workarounds

Users who cannot immediately upgrade `docling-core` can alternatively ensure that the installed version of `PyYAML` is **5.4 or greater**, which supposedly patches CVE-2020-14343.

### References

* GitHub Issue: #482
* Upstream Advisory: CVE-2020-14343
* Fix Release: [v2.48.4](https://github.com/docling-project/docling-core/releases/tag/v2.48.4)
