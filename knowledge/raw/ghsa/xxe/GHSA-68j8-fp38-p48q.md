# Gematik Referenzvalidator has an XXE vulnerability that can lead to a Server Side Request Forgery attack

**GHSA**: GHSA-68j8-fp38-p48q | **CVE**: CVE-2024-46984 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-611

**Affected Packages**:
- **de.gematik.refv.commons:commons** (maven): < 2.5.1

## Description

### Impact
The profile location routine in the referencevalidator commons package is vulnerable to [XML External Entities](https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE)) attack due to insecure defaults of the used Woodstox WstxInputFactory. A malicious XML resource can lead to network requests issued by referencevalidator and thus to a [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) attack.

The vulnerability impacts applications which use referencevalidator to process XML resources from untrusted sources. 

### Patches
The problem has been patched with the [2.5.1 version](https://github.com/gematik/app-referencevalidator/releases/tag/2.5.1) of the referencevalidator. Users are strongly recommended to update to this version or a more recent one. 

### Workarounds
A pre-processing or manual analysis of input XML resources on existence of DTD definitions or external entities can mitigate the problem.

### References
- [OWASP Top 10 XXE](https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE)#)
- [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#transformerfactory)
