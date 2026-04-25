# Lollms has an Improper Access Control vulnerability

**GHSA**: GHSA-82fw-ch24-j34w | **CVE**: CVE-2026-1117 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-284

**Affected Packages**:
- **lollms** (pip): < 2.1.0

## Description

A vulnerability in the `lollms_generation_events.py` component of parisneo/lollms version 5.9.0 allows unauthenticated access to sensitive Socket.IO events. The `add_events` function registers event handlers such as `generate_text`, `cancel_generation`, `generate_msg`, and `generate_msg_from` without implementing authentication or authorization checks. This allows unauthenticated clients to execute resource-intensive or state-altering operations, leading to potential denial of service, state corruption, and race conditions. Additionally, the use of global flags (`lollmsElfServer.busy`, `lollmsElfServer.cancel_gen`) for state management in a multi-client environment introduces further vulnerabilities, enabling one client's actions to affect the server's state and other clients' operations. The lack of proper access control and reliance on insecure global state management significantly impacts the availability and integrity of the service.
