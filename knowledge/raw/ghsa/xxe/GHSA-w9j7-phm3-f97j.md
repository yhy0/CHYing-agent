# Ucum-java has an XXE vulnerability in XML parsing

**GHSA**: GHSA-w9j7-phm3-f97j | **CVE**: CVE-2024-55887 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-611

**Affected Packages**:
- **org.fhir:ucum** (maven): < 1.0.9

## Description

### Impact
XML parsing performed by the UcumEssenceService is vulnerable to XML external entity injections. A processed XML file with a malicious DTD tag could produce XML containing data from the host system. This impacts use cases where ucum is being used to within a host where external clients can submit XML.

### Patches
Release 1.0.9 of ucum fixes this vulnerability

### Workarounds
Ensure that the source xml for instantiating UcumEssenceService is trusted.

### References
* https://cwe.mitre.org/data/definitions/611.html
* https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#jaxp-documentbuilderfactory-saxparserfactory-and-dom4j

