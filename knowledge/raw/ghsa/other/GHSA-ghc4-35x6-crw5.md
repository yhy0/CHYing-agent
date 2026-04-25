# Envoy has RBAC Header Validation Bypass via Multi-Value Header Concatenation

**GHSA**: GHSA-ghc4-35x6-crw5 | **CVE**: CVE-2026-26308 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-20, CWE-863

**Affected Packages**:
- **github.com/envoyproxy/envoy** (go): = 1.37.0
- **github.com/envoyproxy/envoy** (go): >= 1.36.0, <= 1.36.4
- **github.com/envoyproxy/envoy** (go): >= 1.35.0, <= 1.35.8
- **github.com/envoyproxy/envoy** (go): <= 1.34.12

## Description

## 1. Summary
The Envoy RBAC (Role-Based Access Control) filter contains a logic vulnerability in how it validates HTTP headers when multiple values are present for the same header name. Instead of validating each header value individually, Envoy concatenates all values into a single comma-separated string. This behavior allows attackers to bypass RBAC policies—specifically "Deny" rules—by sending duplicate headers, effectively obscuring the malicious value from exact-match mechanisms.

## 2. Attack Scenario
Consider an environment where an administrator wants to block external access to internal resources using a specific header flag.

### Configuration
The Envoy proxy is configured with a **Deny** rule to reject requests containing the header `internal: true`.
* **Rule Type:** Exact Match
* **Target:** `internal` header must not equal `true`.

### The Bypass Logic
1.  **Standard Request (Blocked):**
    * **Input:** `internal: true`
    * **Envoy Processing:** Sees string `"true"`.
    * **Result:** Match found. **Request Denied.**

2.  **Exploit Request (Bypassed):**
    * **Input:**
        ```http
        internal: true
        internal: true
        ```
    * **Envoy Processing:** Concatenates values into `"true,true"`.
    * **Matcher Evaluation:** Does `"true,true"` equal `"true"`? **No.**
    * **Result:** The Deny rule fails to trigger. **Request Allowed.**

## 3. Implications
* **RBAC Bypass:** Remote attackers can bypass configured access controls.
* **Unauthorized Access:** Sensitive internal resources or administrative endpoints protected by header-based Deny rules become accessible.
* **Risk:** High, particularly for deployments relying on "Exact Match" strategies for security blocking.

## 4. Reproduction Steps
To verify this vulnerability:

1.  **Deploy Envoy:** Configure an instance with an RBAC **Deny** rule that performs an **exact match** on a specific header (e.g., `internal: true`).
2.  **Baseline Test:** Send a request containing the header `internal: true`.
    * *Observation:* Envoy blocks this request (HTTP 403).
3.  **Exploit Test:** Send a second request containing the same header twice:
    ```http
    GET /restricted-resource HTTP/1.1
    Host: example.com
    internal: true
    internal: true
    ```
    * *Observation:* Envoy allows the request, granting access to the resource.

## 6. Recommendations
**Fix Header Validation Logic:**
Modify the RBAC filter to validate each header value instance individually. Avoid relying on the concatenated string output of `getAllOfHeaderAsString()` for security-critical matching unless the matcher is explicitly designed to parse comma-separated lists.

** Examine the DENY role to use a Regex style fix.

**Credit:** Dor Konis
