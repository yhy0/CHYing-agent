# Yggdrasil Vulnerable to Local Privilege Escalation

**GHSA**: GHSA-rpg2-jvhp-h354 | **CVE**: CVE-2025-3931 | **Severity**: high (CVSS 7.8)

**CWE**: CWE-280

**Affected Packages**:
- **github.com/redhatinsights/yggdrasil** (go): <= 0.4.6

## Description

A flaw was found in Yggdrasil, which acts as a system broker, allowing the processes to communicate to other children's "worker" processes through the DBus component. Yggdrasil creates a DBus method to dispatch messages to workers. However, it misses authentication and authorization checks, allowing every system user to call it. One available Yggdrasil worker acts as a package manager with capabilities to create and enable new repositories and install or remove packages. 

This flaw allows an attacker with access to the system to leverage the lack of authentication on the dispatch message to force the Yggdrasil worker to install arbitrary RPM packages. This issue results in local privilege escalation, enabling the attacker to access and modify sensitive system data.
