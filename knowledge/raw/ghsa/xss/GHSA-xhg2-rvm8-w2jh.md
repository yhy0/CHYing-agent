# Rancher Vulnerable to Cross-site Request Forgery (CSRF)

**GHSA**: GHSA-xhg2-rvm8-w2jh | **CVE**: CVE-2019-13209 | **Severity**: high (CVSS 8.7)

**CWE**: CWE-79, CWE-352

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.0.0, < 2.0.16
- **github.com/rancher/rancher** (go): >= 2.1.0, < 2.1.11
- **github.com/rancher/rancher** (go): >= 2.2.0, < 2.2.5

## Description

Rancher 2 through 2.2.4 is vulnerable to a Cross-Site Websocket Hijacking attack that allows an exploiter to gain access to clusters managed by Rancher. The attack requires a victim to be logged into a Rancher server, and then to access a third-party site hosted by the exploiter. Once that is accomplished, the exploiter is able to execute commands against the cluster's Kubernetes API with the permissions and identity of the victim.
