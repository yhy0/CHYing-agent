# Arcane Has a Command Injection in Arcane Updater Lifecycle Labels That Enables RCE

**GHSA**: GHSA-gjqq-6r35-w3r8 | **CVE**: CVE-2026-23520 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-78

**Affected Packages**:
- **github.com/getarcaneapp/arcane/backend** (go): < 0.0.0-20260114065515-5a9c2f92e11f

## Description

## Summary

Arcane’s updater service supported lifecycle labels `com.getarcaneapp.arcane.lifecycle.pre-update` and `com.getarcaneapp.arcane.lifecycle.post-update` that allowed defining a command to run before or after a container update. The label value is passed directly to /bin/sh -c without sanitization or validation.

Because any authenticated user (not limited to administrators) can create projects through the API, an attacker can create a project that specifies one of these lifecycle labels with a malicious command. When an administrator later triggers a container update (either manually or via scheduled update checks), Arcane reads the lifecycle label and executes its value as a shell command inside the container.

If the container is configured with host volume mounts in its Compose definition, the executed command may be able to read from or write to the host filesystem through the mounted paths. This can enable data theft and, in some configurations, escalation to full host compromise (for example, if /var/run/docker.sock is mounted).

### Impact

- Remote code execution (RCE) within the updated container context.
- Host filesystem access when host volumes are mounted into the container.
- Potential data exfiltration via outbound network requests or by exposing readable files.
- Potential full host compromise if sensitive mounts are present (e.g., /var/run/docker.sock).

### Patches
The lifecycle labels `com.getarcaneapp.arcane.lifecycle.pre-update` and `com.getarcaneapp.arcane.lifecycle.post-update` have been removed to eliminate this attack surface.
