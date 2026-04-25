# FrankenPHP has delayed propagation of security fixes in upstream base images

**GHSA**: GHSA-x9p2-77v6-6vhf | **CVE**: N/A | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-1395

**Affected Packages**:
- **github.com/dunglas/frankenphp** (go): < 1.1.11

## Description

# Delayed propagation of security fixes in upstream base images

## Summary

**Vulnerability in base Docker images (PHP, Go, and Alpine) not automatically propagating to FrankenPHP images.**

FrankenPHP's container images were previously built only when specific version tags were updated or when manual triggers were initiated. This meant that if an upstream base image (such as Alpine Linux or official PHP/Go images) received a security patch under an existing tag, the FrankenPHP image would remain on the older, vulnerable version of those base layers.

## Impact

Users pulling FrankenPHP images may have been running environments with known vulnerabilities in underlying system libraries (e.g., `libcrypto3`) even if they were using the "latest" version of a specific FrankenPHP tag.

Specifically, this includes vulnerabilities recently patched in **Alpine 3.20.9, 3.21.6, 3.22.3, and 3.23.3**, such as **CVE-2025-15467** (Remote Code Execution in `libcrypto3`).

## Details

The issue was a lack of automated "staleness" detection in the CI/CD pipeline.

Unless explicitly told, our build server was building new Docker images only when a new tag for base images was created. However, base images such as Alpine, PHP, and Go usually overwrite existing Docker tags to apply security fixes, which wasn't triggering a new build on our side.

## Patches

As of **February 4, 2026**, the CI/CD pipeline has been updated.

* **Automated Detection:** A daily check is now performed to compare the digest of local base images against upstream registries.
* **Auto-Rebuild:** If a change is detected in base images (even if the tag name remains the same), FrankenPHP images are automatically rebuilt and re-pushed.

**Users are advised to pull the latest versions of their specific tags to receive these updates.**

## Workarounds

You can force a local rebuild of your environment using the `--pull` flag to ensure you are fetching the latest patched base layers:

```bash
docker pull dunglas/frankenphp:latest
# If building your own image based on FrankenPHP
docker build --pull -t my-app .
```

## References

* [Alpine Linux Security Advisories](https://www.alpinelinux.org/posts/Alpine-3.20.9-3.21.6-3.22.3-3.23.3-released.html)
* **CVE-2025-15467** (RCE in libcrypto3)

## Credits

Thanks to [Tim Nelles](https://timnelles.de/) for reporting and fixing this issue.
