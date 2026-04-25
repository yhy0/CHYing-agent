# Flux CLI Workload Injection

**GHSA**: GHSA-xwf3-6rgv-939r | **CVE**: CVE-2022-36035 | **Severity**: high (CVSS 7.8)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/fluxcd/flux2** (go): >= 0.21.0, < 0.32.0

## Description

Flux CLI allows users to deploy Flux components into a Kubernetes cluster via command-line. The vulnerability allows other applications to replace the Flux deployment information with arbitrary content which is deployed into the target Kubernetes cluster instead.

The vulnerability is due to the improper handling of user-supplied input, which results in a path traversal that can be controlled by the attacker.

### Impact
Users sharing the same shell between other applications and the Flux CLI commands could be affected by this vulnerability.

In some scenarios no errors may be presented, which may cause end users not to realise that something is amiss.

### Workarounds

A safe workaround is to execute Flux CLI in ephemeral and isolated shell environments, which can ensure no persistent values exist from previous processes. However, upgrading to the latest version of the CLI is still the recommended mitigation strategy.

### Credits
The Flux engineering team found and patched this vulnerability.

### For more information

If you have any questions or comments about this advisory:
- Open an issue in any of the affected repositories.
- Contact us at the CNCF Flux Channel.

