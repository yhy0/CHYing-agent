# XXE vulnerability in XSLT parsing in `org.hl7.fhir.publisher`

**GHSA**: GHSA-8c3x-hq82-gjcm | **CVE**: CVE-2024-52807 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-611

**Affected Packages**:
- **org.hl7.fhir.publisher:org.hl7.fhir.publisher.cli** (maven): < 1.7.4
- **org.hl7.fhir.publisher:org.hl7.fhir.publisher.core** (maven): < 1.7.4

## Description

### Impact
XSLT transforms performed by various components are vulnerable to XML external entity injections. A processed XML file with a malicious DTD tag ( ]> could produce XML containing data from the host system. This impacts use cases where org.hl7.fhir.publisher is being used to within a host where external clients can submit XML.

A previous release provided an incomplete solution revealed by new testing. 

### Patches
This issue has been patched as of version 1.7.4

### Workarounds
None

### References
[Previous Advisory for Incomplete solution](https://github.com/HL7/fhir-ig-publisher/security/advisories/GHSA-59rq-22fm-x8q5)
[MITRE CWE](https://cwe.mitre.org/data/definitions/611.html)
[OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#transformerfactory)
