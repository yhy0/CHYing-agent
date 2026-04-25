# Privileged OpenBao Operator May Execute Code on the Underlying Host

**GHSA**: GHSA-xp75-r577-cvhp | **CVE**: CVE-2025-54997 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-94

**Affected Packages**:
- **github.com/openbao/openbao** (go): >= 0.1.0, < 2.3.2
- **github.com/openbao/openbao** (go): < 0.0.0-20250806194004-a14053c9679d

## Description

### Impact

Under certain threat models, OpenBao operators with privileged API access may not be system administrators and thus normally lack the ability to update binaries or execute code on the system. Additionally, privileged API operators should be unable to perform TCP connections to arbitrary hosts in the environment OpenBao is executing within. The API-driven audit subsystem granted privileged API operators the ability to do both with an attacker-controlled log prefix. Access to these endpoints should be restricted.

### Patches

OpenBao v2.3.2 will patch this issue.

### Workarounds

Users may deny all access to the `sys/audit/*` interface (with `create` and `update`) permission via policies with explicit deny grants. This would not restrict `root` level operators, however, for whom there are no workarounds. 

This interface allowed arbitrary filesystem and network (write) access as the user the OpenBao server was running as; in conjunction with allowing custom plugins or other system processes this may enable code execution.

### References

This issue was disclosed to HashiCorp and is the OpenBao equivalent of the following tickets:

- https://discuss.hashicorp.com/t/hcsec-2025-14-privileged-vault-operator-may-execute-code-on-the-underlying-host/76033
- https://nvd.nist.gov/vuln/detail/CVE-2025-6000
