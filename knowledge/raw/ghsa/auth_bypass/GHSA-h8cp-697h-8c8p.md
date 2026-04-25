# Step CA Has Authorization Bypass in ACME and SCEP Provisioners

**GHSA**: GHSA-h8cp-697h-8c8p | **CVE**: CVE-2025-44005 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-306

**Affected Packages**:
- **github.com/smallstep/certificates** (go): <= 0.28.4

## Description

## Summary

A security fix is now available for Step CA that resolves a vulnerability affecting deployments configured with ACME and/or SCEP provisioners.
All operators running these provisioners should upgrade to the latest release (`v0.29.0`) immediately.

The issue was discovered and disclosed by a research team during a security review. There is no evidence of active exploitation.

To limit exploitation risk during a coordinated disclosure window, we are withholding detailed technical information for now. A full write-up will be published in several weeks.

---

## Embargo List

If your organization runs Step CA in production and would like advance, embargoed notification of future security updates, visit https://u.step.sm/disclosure to request inclusion on our embargo list.

---

## Acknowledgements

This issue was identified and reported by Stephen Kubik of the Cisco Advanced Security Initiatives Group (ASIG)

---

Stay safe, and thank you for helping us keep the ecosystem secure.
