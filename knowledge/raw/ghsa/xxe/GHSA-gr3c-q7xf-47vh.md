# XXE vulnerability in XSLT parsing in `org.hl7.fhir.core`

**GHSA**: GHSA-gr3c-q7xf-47vh | **CVE**: CVE-2024-52007 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-611

**Affected Packages**:
- **ca.uhn.hapi.fhir:org.hl7.fhir.dstu3** (maven): < 6.4.0
- **ca.uhn.hapi.fhir:org.hl7.fhir.r4** (maven): < 6.4.0
- **ca.uhn.hapi.fhir:org.hl7.fhir.r4b** (maven): < 6.4.0
- **ca.uhn.hapi.fhir:org.hl7.fhir.r5** (maven): < 6.4.0
- **ca.uhn.hapi.fhir:org.hl7.fhir.utilities** (maven): < 6.4.0
- **ca.uhn.hapi.fhir:org.hl7.fhir.dstu2016may** (maven): < 6.4.0

## Description

### Summary
XSLT parsing performed by various components are vulnerable to XML external entity injections. A processed XML file with a malicious DTD tag ( <!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]> could produce XML containing data from the host system. This impacts use cases where org.hl7.fhir.core is being used to within a host where external clients can submit XML.

### Details
This is related to https://github.com/hapifhir/org.hl7.fhir.core/security/advisories/GHSA-6cr6-ph3p-f5rf, in which its fix ( https://github.com/hapifhir/org.hl7.fhir.core/issues/1571, https://github.com/hapifhir/org.hl7.fhir.core/pull/1717) was incomplete. 

### References
https://cwe.mitre.org/data/definitions/611.html
https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#jaxp-documentbuilderfactory-saxparserfactory-and-dom4j
