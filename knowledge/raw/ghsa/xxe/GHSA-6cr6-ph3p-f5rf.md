# XXE vulnerability in XSLT transforms in `org.hl7.fhir.core`

**GHSA**: GHSA-6cr6-ph3p-f5rf | **CVE**: CVE-2024-45294 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-611

**Affected Packages**:
- **ca.uhn.hapi.fhir:org.hl7.fhir.dstu2016may** (maven): < 6.3.23
- **ca.uhn.hapi.fhir:org.hl7.fhir.dstu3** (maven): < 6.3.23
- **ca.uhn.hapi.fhir:org.hl7.fhir.r4** (maven): < 6.3.23
- **ca.uhn.hapi.fhir:org.hl7.fhir.r4b** (maven): < 6.3.23
- **ca.uhn.hapi.fhir:org.hl7.fhir.r5** (maven): < 6.3.23
- **ca.uhn.hapi.fhir:org.hl7.fhir.utilities** (maven): < 6.3.23

## Description

### Impact
XSLT transforms performed by various components are vulnerable to XML external entity injections. A processed XML file with a malicious DTD tag ( `<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>` could produce XML containing data from the host system. This impacts use cases where org.hl7.fhir.core is being used to within a host where external clients can submit XML.

### Patches
This issue has been patched in release 6.3.23

### Workarounds
None.

### References
[MITRE CWE](https://cwe.mitre.org/data/definitions/611.html)
[OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#transformerfactory)

