# Buildkit's interactive containers API does not validate entitlements check

**GHSA**: GHSA-wr6v-9f75-vh2g | **CVE**: CVE-2024-23653 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/moby/buildkit** (go): < 0.12.5

## Description

### Impact
In addition to running containers as build steps, BuildKit also provides APIs for running interactive containers based on built images. It was possible to use these APIs to ask BuildKit to run a container with elevated privileges. Normally, running such containers is only allowed if special `security.insecure` entitlement is enabled both by buildkitd configuration and allowed by the user initializing the build request.

### Patches
The issue has been fixed in v0.12.5 .

### Workarounds
Avoid using BuildKit frontends from untrusted sources. A frontend image is usually specified as the `#syntax` line on your Dockerfile, or with `--frontend` flag when using `buildctl build` command.

### References


