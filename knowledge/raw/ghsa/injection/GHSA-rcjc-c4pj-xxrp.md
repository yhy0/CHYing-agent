# Apache Derby: LDAP injection vulnerability in authenticator

**GHSA**: GHSA-rcjc-c4pj-xxrp | **CVE**: CVE-2022-46337 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-74, CWE-94

**Affected Packages**:
- **org.apache.derby:derby** (maven): >= 10.1.1.0, < 10.14.3
- **org.apache.derby:derby** (maven): >= 10.15.0.0, < 10.15.2.1
- **org.apache.derby:derby** (maven): >= 10.16.0.0, < 10.16.1.2
- **org.apache.derby:derby** (maven): >= 10.17.0.0, < 10.17.1.0

## Description

A cleverly devised username might bypass LDAP authentication checks. In LDAP-authenticated Derby installations, this could let an attacker fill up the disk by creating junk Derby databases. In LDAP-authenticated Derby installations, this could also allow the attacker to execute malware which was visible to and executable by the account which booted the Derby server. In LDAP-protected databases which weren't also protected by SQL GRANT/REVOKE authorization, this vulnerability could also let an attacker view and corrupt sensitive data and run sensitive database functions and procedures.

Mitigation:

Users should upgrade to Java 21 and Derby 10.17.1.0.

Alternatively, users who wish to remain on older Java versions should build their own Derby distribution from one of the release families to which the fix was backported: 10.16, 10.15, and 10.14. Those are the releases which correspond, respectively, with Java LTS versions 17, 11, and 8.
