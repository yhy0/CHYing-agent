# Rancher Remote Code Execution via Cluster/Node Drivers

**GHSA**: GHSA-h99m-6755-rgwc | **CVE**: CVE-2024-22036 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-269

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.7.0, < 2.7.16
- **github.com/rancher/rancher** (go): >= 2.8.0, < 2.8.9
- **github.com/rancher/rancher** (go): >= 2.9.0, < 2.9.3

## Description

### Impact
A vulnerability has been identified within Rancher where a cluster or node driver can be used to escape the `chroot` jail and gain root access to the Rancher container itself. In production environments, further privilege escalation is possible based on living off the land within the Rancher container itself. For the test and development environments, based on a –privileged Docker container, it is possible to escape the Docker container and gain execution access on the host system. 

This happens because:
- During startup, Rancher appends the `/opt/drivers/management-state/bin` directory to the `PATH` environment variable.
- In Rancher, the binaries `/usr/bin/rancher-machine`, `/usr/bin/helm_v3`, and `/usr/bin/kustomize` are assigned a UID of 1001 and a GID of 127 instead of being owned by the root user.
- Rancher employs a jail mechanism to isolate the execution of node drivers from the main process. However, the drivers are executed with excessive permissions.
- During the registration of new node drivers, its binary is executed with the same user as the parent process, which could enable an attacker to gain elevated privileges by registering a malicious driver.
- Lack of validation on the driver file type, which allows symbolic links to be used.


Please consult the associated  [MITRE ATT&CK - Technique - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) and [MITRE ATT&CK - Technique - Execution](https://attack.mitre.org/tactics/TA0002/) for further information about this category of attack.

**Since they run at a privileged level, it is recommended to use trusted drivers only.**

### Patches
The fix involves some key areas with the following changes:

Fixing the `PATH` environment variable:
- Remove the step that appends `/opt/drivers/management-state/bin` to the `PATH` environment variable.

Binaries permissions:
- Correct the permission of the binaries `/usr/bin/rancher-machine`, `/usr/bin/helm_v3`, and `/usr/bin/kustomize` so that they are owned by the root user.

Improving Rancher jail security mechanism:
- A new group `jail-accessors` has been created, and the rancher user has been added to this group.
- The `jail-accessors` group is granted read and execute permissions for the directories `/var/lib/rancher`, `/var/lib/cattle`, and `/usr/local/bin`.
- The jail mechanism has been enhanced to execute commands using the non-root `rancher` user and the `jail-accessors` group. Additionally, a new setting, `UnprivilegedJailUser`, has been introduced to manage this behavior, allowing users to opt-out if they need to run drivers in a more privileged context.
- Limit the devices copied to the jail directory to a minimal set.

Fixing node driver registration:
- The `NewPlugin(driver)` function in the `rancher/machine` module has been updated to allow setting the UID and GID for starting the plugin server. If the environment variables `MACHINE_PLUGIN_UID` and `MACHINE_PLUGIN_GID` are set, their values will be used to configure the user credentials for launching the plugin server. 
- Rancher now sets these environment variables with a non-root UID and GID before invoking the `NewPlugin(driver)` function and then unsets them after retrieving the creation flags.

Improvements on driver package:
- The `driver` package has been revised to verify that the downloaded driver binary is a regular file.
- The `driver` package has been revised to verify that the target file in the downloaded tar file is a regular file.
- The `driver` package now executes the downloaded driver binary within a jail, with a default timeout of 5 seconds.

Other improvements:
- The helm package has been updated to ensure appropriate permissions are set on the generated kubeconfig file.
- The `nodeConfig` package has been updated to ensure proper permissions are applied when extracting the node configuration.

Patched versions include releases `2.7.16`, `2.8.9` and `2.9.3`.

### Workarounds
If you can't upgrade to a fixed version, please make sure that:
1. Drivers are only executed from trusted sources.
2. The use of Admins/Restricted Admins is limited to trusted users.


### References
If you have any questions or comments about this advisory:
- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
