# mount destinations can be swapped via symlink-exchange to cause mounts outside the rootfs

**GHSA**: GHSA-c3xm-pvg7-gh7r | **CVE**: CVE-2021-30465 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-22, CWE-362, CWE-367

**Affected Packages**:
- **github.com/opencontainers/runc** (go): <= 1.0.0-rc94

## Description

### Summary

runc 1.0.0-rc94 and earlier are vulnerable to a symlink exchange attack whereby
an attacker can request a seemingly-innocuous container configuration that
actually results in the host filesystem being bind-mounted into the container
(allowing for a container escape). CVE-2021-30465 has been assigned for this
issue.

An attacker must have the ability to start containers using some kind of custom
volume configuration, and while recommended container hardening mechanisms such
as LSMs (AppArmor/SELinux) and user namespaces will restrict the amount of
damage an attacker could do, they do not block this attack outright. We have a
reproducer using Kubernetes (and the below description mentions
Kubernetes-specific paths), but this is not a Kubernetes-specific issue.

The now-released [runc v1.0.0-rc95][release] contains a fix for this issue, we
recommend users update as soon as possible.

[release]: https://github.com/opencontainers/runc/releases/tag/v1.0.0-rc95

### Details

In circumstances where a container is being started, and runc is mounting
inside a volume shared with another container (which is conducting a
symlink-exchange attack), runc can be tricked into mounting outside of the
container rootfs by swapping the target of a mount with a symlink due to a
time-of-check-to-time-of-use (TOCTTOU) flaw. This is fairly similar in style to
previous TOCTTOU attacks (and is a problem we are working on solving with
libpathrs).

However, this alone is not useful because this happens inside a mount namespace
with `MS_SLAVE` propagation applied to `/` (meaning that the mount doesn't
appear on the host -- it's only a "host-side mount" inside the container's
namespace). To exploit this, you must have additional mount entries in the
configuration that use some subpath of the mounted-over host path as a source
for a subsequent mount.

However, it turns out with some container orchestrators (such as Kubernetes --
though it is very likely that other downstream users of runc could have similar
behaviour be accessible to untrusted users), the existence of additional volume
management infrastructure allows this attack to be applied to gain access to
the host filesystem without requiring the attacker to have completely arbitrary
control over container configuration.

In the case of Kubernetes, this is exploitable by creating a symlink in a
volume to the top-level (well-known) directory where volumes are sourced from
(for instance,
`/var/lib/kubelet/pods/$MY_POD_UID/volumes/kubernetes.io~empty-dir`), and then
using that symlink as the target of a mount. The source of the mount is an
attacker controlled directory, and thus the source directory from which
subsequent mounts will occur is an attacker-controlled directory. Thus the
attacker can first place a symlink to `/` in their malicious source directory
with the name of a volume, and a subsequent mount in the container will
bind-mount `/` into the container.

Applying this attack requires the attacker to start containers with a slightly
peculiar volume configuration (though not explicitly malicious-looking such as
bind-mounting `/` into the container explicitly), and be able to run malicious
code in a container that shares volumes with said volume configuration. It
helps the attacker if the host paths used for volume management are well known,
though this is not a hard requirement.

### Patches
This has been patched in runc 1.0.0-rc95, and users should upgrade as soon as
possible. The patch itself can be found [here](https://github.com/opencontainers/runc/commit/0ca91f44f1664da834bc61115a849b56d22f595f).

### Workarounds

There are no known workarounds for this issue.

However, users who enforce running containers with more confined security
profiles (such as reduced capabilities, not running code as root in the
container, user namespaces, AppArmor/SELinux, and seccomp) will restrict what
an attacker can do in the case of a container breakout -- we recommend users
make use of strict security profiles if possible (most notably user namespaces
-- which can massively restrict the impact a container breakout can have on the
host system).

### References
* [commit](https://github.com/opencontainers/runc/commit/0ca91f44f1664da834bc61115a849b56d22f595f)
* [seclists public disclosure](https://www.openwall.com/lists/oss-security/2021/05/19/2)

### Credit

Thanks to Etienne Champetier for discovering and disclosing this vulnerability,
to Noah Meyerhans for writing the first draft of this patch, and to Samuel Karp
for testing it.

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [our issue tracker](https://github.com/opencontainers/runc/issues).
* Email us at <security@opencontainers.org>.
