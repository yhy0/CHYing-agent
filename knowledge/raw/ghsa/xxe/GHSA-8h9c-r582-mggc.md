# OWSLib vulnerable to XML External Entity (XXE) Injection

**GHSA**: GHSA-8h9c-r582-mggc | **CVE**: CVE-2023-27476 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-611

**Affected Packages**:
- **OWSLib** (pip): < 0.28.1

## Description

### Impact

OWSLib's XML parser (which supports both `lxml` and `xml.etree`) does not disable entity resolution for `lxml`, and could lead to arbitrary file reads from an attacker-controlled XML payload. This affects all XML parsing in the codebase.

### Patches

- Use only lxml for XML handling, adding `resolve_entities=False` to `lxml`'s parser: https://github.com/geopython/OWSLib/pull/863

### Workarounds

```python
patch_well_known_namespaces(etree)
etree.set_default_parser(
    parser=etree.XMLParser(resolve_entities=False)
)
```

### References

- [`GHSL-2022-131`](https://securitylab.github.com/advisories/GHSL-2022-131_OWSLib/)

