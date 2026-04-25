# Attacker can cause Kyverno user to unintentionally consume insecure image

**GHSA**: GHSA-3hfq-cx9j-923w | **CVE**: CVE-2023-47630 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-200, CWE-345

**Affected Packages**:
- **github.com/kyverno/kyverno** (go): < 1.10.5

## Description

An issue was found in Kyverno that allowed an attacker to control the digest of images used by Kyverno users. The issue would require the attacker to compromise the registry that the Kyverno fetch their images from. The attacker could then return a vulnerable image to the the user and leverage that to further escalate their position. As such, the attacker would need to know which images the Kyverno user consumes and know of one of multiple exploitable vulnerabilities in previous digests of the images. Alternatively, if the attacker has compromised the registry, they could craft a malicious image with a different digest with intentionally placed vulnerabilities and deliver the image to the user. 

An attacker was not be able to control other parameters of the image than the digest by exploiting this vulnerability.

Users pulling their images from trusted registries are not impacted by this vulnerability. There is no evidence of this being exploited in the wild.

The issue has been patched in 1.11.0. 

The vulnerability was found during an ongoing security audit of Kyverno conducted by Ada Logics, facilitated by OSTIF and funded by the CNCF.

Members of the community have raised concerns over the similarity between this vulnerability and the one identified with CVE-2023-46737; They are two different issues with two different root causes and different levels of impact. Some differences are:

- The current advisory (GHSA-3hfq-cx9j-923w) has its root cause in Kyverno whereas the root cause of CVE-2023-46737 is in Cosigns code base. 
- The impact of the current advisory (GHSA-3hfq-cx9j-923w) is that an attacker can trick Kyverno into consuming a different image than the one the user requested; The impact of CVE-2023-46737 is an endless data attack resulting in a denial-of-service.
- The fix of the current advisory (GHSA-3hfq-cx9j-923w) does not result in users being secure from CVE-2023-46737 and vice versa.
