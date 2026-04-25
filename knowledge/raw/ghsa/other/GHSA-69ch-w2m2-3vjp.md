# golang.org/x/text/language Denial of service via crafted Accept-Language header

**GHSA**: GHSA-69ch-w2m2-3vjp | **CVE**: CVE-2022-32149 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-772

**Affected Packages**:
- **golang.org/x/text** (go): < 0.3.8

## Description

The BCP 47 tag parser has quadratic time complexity due to inherent aspects of its design. Since the parser is, by design, exposed to untrusted user input, this can be leveraged to force a program to consume significant time parsing Accept-Language headers. The parser cannot be easily rewritten to fix this behavior for various reasons. Instead the solution implemented in this CL is to limit the total complexity of tags passed into ParseAcceptLanguage by limiting the number of dashes in the string to 1000. This should be more than enough for the majority of real world use cases, where the number of tags being sent is likely to be in the single digits.

### Specific Go Packages Affected
golang.org/x/text/language
