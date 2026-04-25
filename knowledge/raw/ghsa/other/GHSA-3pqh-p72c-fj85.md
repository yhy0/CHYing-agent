# Improper Preservation of Permissions in github.com/cloudflare/cfrpki/cmd/octorpki

**GHSA**: GHSA-3pqh-p72c-fj85 | **CVE**: CVE-2021-3978 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-269, CWE-281

**Affected Packages**:
- **github.com/cloudflare/cfrpki** (go): < 1.4.2

## Description

### Impact

When copying files with rsync, octorpki uses the "-a" flag 0, which forces rsync to copy binaries with the suid bit set as root. Since the provided service definition defaults to root (https://github.com/cloudflare/cfrpki/blob/master/package/octorpki.service) this could allow for a vector, when combined with another vulnerability that causes octorpki to process a malicious TAL file, for a local privilege escalation.  

## For more information

If you have any questions or comments about this advisory email us at security@cloudflare.com
