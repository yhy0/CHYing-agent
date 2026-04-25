# Connecting to a malicious Codespaces via GH CLI could allow command execution on the user's computer

**GHSA**: GHSA-p2h2-3vg9-4p87 | **CVE**: CVE-2024-52308 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-77

**Affected Packages**:
- **github.com/cli/cli/v2** (go): <= 2.61.0
- **github.com/cli/cli** (go): < 2.62.0

## Description

### Summary

A security vulnerability has been identified in GitHub CLI that could allow remote code execution (RCE) when users connect to a malicious Codespace SSH server and use the `gh codespace ssh` or `gh codespace logs` commands.

### Details

The vulnerability stems from the way GitHub CLI handles SSH connection details when executing commands. When developers connect to remote Codespaces, they typically use a SSH server running within a devcontainer, often provided through the [default devcontainer image](https://docs.github.com/en/codespaces/setting-up-your-project-for-codespaces/adding-a-dev-container-configuration/introduction-to-dev-containers#using-the-default-dev-container-configuration).  GitHub CLI [retrieves SSH connection details](https://github.com/cli/cli/blob/30066b0042d0c5928d959e288144300cb28196c9/internal/codespaces/rpc/invoker.go#L230-L244), such as remote username, which is used in [executing `ssh` commands](https://github.com/cli/cli/blob/e356c69a6f0125cfaac782c35acf77314f18908d/pkg/cmd/codespace/ssh.go#L263) for `gh codespace ssh` or `gh codespace logs` commands.

This exploit occurs when a malicious third-party devcontainer contains a modified SSH server that injects `ssh` arguments within the SSH connection details. `gh codespace ssh` and `gh codespace logs` commands could execute arbitrary code on the user's workstation if the remote username contains something like `-oProxyCommand="echo hacked" #`.  The `-oProxyCommand` flag causes `ssh` to execute the provided command while `#` shell comment causes any other `ssh` arguments to be ignored.

In `2.62.0`, the remote username information is being validated before being used.

### Impact

Successful exploitation could lead to arbitrary code execution on the user's workstation, potentially compromising the user's data and system.

### Remediation and Mitigation

1. Upgrade `gh` to `2.62.0`
2. Exercise caution when using custom devcontainer images, prefer default or pre-built devcontainers from trusted sources.
