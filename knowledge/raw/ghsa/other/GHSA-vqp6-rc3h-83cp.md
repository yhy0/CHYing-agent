# Tailscale Windows daemon is vulnerable to RCE via CSRF

**GHSA**: GHSA-vqp6-rc3h-83cp | **CVE**: CVE-2022-41924 | **Severity**: critical (CVSS 9.6)

**CWE**: CWE-346, CWE-352

**Affected Packages**:
- **tailscale.com** (go): < 1.32.3

## Description

A vulnerability identified in the Tailscale Windows client allows a malicious website to reconfigure the Tailscale daemon `tailscaled`, which can then be used to remotely execute code.

**Affected platforms:** Windows
**Patched Tailscale client versions:** v1.32.3 or later, v1.33.257 or later (unstable)

### What happened?
In the Tailscale Windows client, the local API was bound to a local TCP socket, and communicated with the Windows client GUI in cleartext with no Host header verification. This allowed an attacker-controlled website visited by the node to rebind DNS to an attacker-controlled DNS server, and then make local API requests in the client, including changing the coordination server to an attacker-controlled coordination server.

### Who is affected?
All Windows clients prior to version v.1.32.3 are affected.

### What should I do?
If you are running Tailscale on Windows, upgrade to v1.32.3 or later to remediate the issue.

### What is the impact?
An attacker-controlled coordination server can send malicious URL responses to the client, including pushing executables or installing an SMB share. These allow the attacker to remotely execute code on the node.

Reviewing all logs confirms this vulnerability was not triggered or exploited. 

### Credits
We would like to thank [Emily Trau](https://github.com/emilytrau) and [Jamie McClymont (CyberCX)](https://twitter.com/JJJollyjim) for reporting this issue. Further detail is available in [their blog post](https://emily.id.au/tailscale).

### References
* [TS-2022-004](https://tailscale.com/security-bulletins/#ts-2022-004)
* [Researcher blog post](https://emily.id.au/tailscale)

### For more information
If you have any questions or comments about this advisory, [contact Tailscale support](https://tailscale.com/contact/support/).

