# MLFlow is vulnerable to DNS rebinding attacks due to a lack of Origin header validation

**GHSA**: GHSA-pgqp-8h46-6x4j | **CVE**: CVE-2025-14279 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-346

**Affected Packages**:
- **mlflow** (pip): < 3.5.0

## Description

MLFlow versions up to and including 3.4.0 are vulnerable to DNS rebinding attacks due to a lack of Origin header validation in the MLFlow REST server. This vulnerability allows malicious websites to bypass Same-Origin Policy protections and execute unauthorized calls against REST endpoints. An attacker can query, update, and delete experiments via the affected endpoints, leading to potential data exfiltration, destruction, or manipulation. The issue is resolved in version 3.5.0.
