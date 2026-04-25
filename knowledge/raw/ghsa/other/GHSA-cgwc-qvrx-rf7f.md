# Remote code execution in pytorch lightning

**GHSA**: GHSA-cgwc-qvrx-rf7f | **CVE**: CVE-2024-5452 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-913, CWE-915

**Affected Packages**:
- **lightning** (pip): < 2.3.3

## Description

A remote code execution (RCE) vulnerability exists in the lightning-ai/pytorch-lightning library version 2.2.1 due to improper handling of deserialized user input and mismanagement of dunder attributes by the `deepdiff` library. The library uses `deepdiff.Delta` objects to modify application state based on frontend actions. However, it is possible to bypass the intended restrictions on modifying dunder attributes, allowing an attacker to construct a serialized delta that passes the deserializer whitelist and contains dunder attributes. When processed, this can be exploited to access other modules, classes, and instances, leading to arbitrary attribute write and total RCE on any self-hosted pytorch-lightning application in its default configuration, as the delta endpoint is enabled by default.
