# Command injection in Git package in Wrangler

**GHSA**: GHSA-qrg7-hfx7-95c5 | **CVE**: CVE-2022-31249 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-77, CWE-78, CWE-88

**Affected Packages**:
- **github.com/rancher/wrangler** (go): >= 0.8.6, < 0.8.11
- **github.com/rancher/wrangler** (go): = 1.0.0
- **github.com/rancher/wrangler** (go): < 0.7.4-security1
- **github.com/rancher/wrangler** (go): >= 0.8.0, < 0.8.5-security1

## Description

### Impact

A command injection vulnerability was discovered in Wrangler's Git package affecting versions up to and including `v1.0.0`.

Wrangler's Git package uses the underlying Git binary present in the host OS or container image to execute Git operations. Specially crafted commands can be passed to Wrangler that will change their behavior and cause confusion when executed through Git, resulting in command injection in the underlying host.

### Workarounds

A workaround is to sanitize input passed to the Git package to remove potential unsafe and ambiguous characters. Otherwise, the best course of action is to update to a patched Wrangler version.

### Patches

Patched versions include `v1.0.1` and later and the backported tags - `v0.7.4-security1`, `v0.8.5-security1` and `v0.8.11`.

### For more information

If you have any questions or comments about this advisory:

* Reach out to [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
* Open an issue in [Rancher](https://github.com/rancher/rancher/issues/new/choose) or [Wrangler](https://github.com/rancher/wrangler/issues/new) repository.
* Verify our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
