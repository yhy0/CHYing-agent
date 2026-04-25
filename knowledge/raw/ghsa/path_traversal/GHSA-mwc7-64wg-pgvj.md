# NiceGUI allows potential access to local file system

**GHSA**: GHSA-mwc7-64wg-pgvj | **CVE**: CVE-2024-32005 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-22, CWE-23

**Affected Packages**:
- **nicegui** (pip): >= 1.4.6, < 1.4.21

## Description

NiceGUI is an easy-to-use, Python-based UI framework. A local file inclusion is present in the NiceUI leaflet component when requesting resource files under the `/_nicegui/{__version__}/resources/{key}/{path:path}` route. 

As a result any file on the backend filesystem which the web server has access to can be read by an attacker with access to the NiceUI leaflet website. 

This vulnerability has been addressed in version 1.4.21. Users are advised to upgrade. There are no known workarounds for this vulnerability.
