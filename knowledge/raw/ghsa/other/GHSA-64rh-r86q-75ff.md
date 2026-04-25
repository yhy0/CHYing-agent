# Hard coded cryptographic key in Kiali

**GHSA**: GHSA-64rh-r86q-75ff | **CVE**: CVE-2020-1764 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-321, CWE-798

**Affected Packages**:
- **github.com/kiali/kiali** (go): < 1.15.1

## Description

A hard-coded cryptographic key vulnerability in the default configuration file was found in Kiali, all versions prior to 1.15.1. A remote attacker could abuse this flaw by creating their own JWT signed tokens and bypass Kiali authentication mechanisms, possibly gaining privileges to view and alter the Istio configuration.
