# HashiCorp go-getter Vulnerable to Code Execution On Git Update Via Git Config Manipulation

**GHSA**: GHSA-xfhp-jf8p-mh5w | **CVE**: CVE-2024-6257 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-77

**Affected Packages**:
- **github.com/hashicorp/go-getter** (go): < 1.7.5

## Description

HashiCorp’s go-getter library can be coerced into executing Git update on an existing maliciously modified Git Configuration, potentially leading to arbitrary code execution. When go-getter is performing a Git operation, go-getter will try to clone the given repository in a specified destination. Cloning initializes a git config to the provided destination and if the repository needs to get updated go-getter will pull the new changes .

An attacker may alter the Git config after the cloning step to set an arbitrary Git configuration to achieve code execution.
