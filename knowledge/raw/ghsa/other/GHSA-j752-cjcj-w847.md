# Dpanel's hard-coded JWT secret leads to remote code execution

**GHSA**: GHSA-j752-cjcj-w847 | **CVE**: CVE-2025-30206 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-321, CWE-453, CWE-547

**Affected Packages**:
- **github.com/donknap/dpanel** (go): < 1.6.1

## Description

### Summary
The Dpanel service contains a hardcoded JWT secret in its default configuration, allowing attackers to generate valid JWT tokens and compromise the host machine.

### Details
The Dpanel service, when initiated using its default configuration, includes a hardcoded JWT secret embedded directly within its source code. This security flaw allows attackers to analyze the source code, discover the embedded secret, and craft legitimate JWT tokens. By forging these tokens, an attacker can successfully bypass authentication mechanisms, impersonate privileged users, and gain unauthorized administrative access. Consequently, this enables full control over the host machine, potentially leading to severe consequences such as sensitive data exposure, unauthorized command execution, privilege escalation, or further lateral movement within the network environment. It is recommended to replace the hardcoded secret with a securely generated value and load it from secure configuration storage to mitigate this vulnerability.


### PoC
The core code snippet is shown below:
```python
import jwt

def generate_jwt(appname):

    payload = {
        "SECRET_KEY"："SECRET_VALUE",
    }
    print("appname:", appname)
    print("payload:", str(payload))
    token = jwt.encode(payload, SECRET_KEY.format(APP_NAME=appname), algorithm="HS256")
    return token

appname = "SECRET_KEY"
token = generate_jwt(appname)
print("url token:", token)
```

### Impact
Attackers who successfully exploit this vulnerability can write arbitrary files to the host machine's file system, and all users with Dpanel versions less than 1.6.1 are affected.
