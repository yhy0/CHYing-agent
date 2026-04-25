# nfpm has incorrect default permissions

**GHSA**: GHSA-w7jw-q4fg-qc4c | **CVE**: CVE-2023-32698 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-276

**Affected Packages**:
- **github.com/goreleaser/nfpm/v2** (go): >= 2.0.0, < 2.29.0
- **github.com/goreleaser/nfpm** (go): >= 0.1.0, <= 1.10.3

## Description

### Summary
When building packages directly from source control, file permissions on the checked-in files are not maintained. 

### Details
When building packages directly from source control, file permissions on the checked-in files are not maintained. When nfpm packaged the files (without extra config for enforcing its own permissions) files could go out with bad permissions (chmod 666 or 777).

### PoC
Create a default nfpm structure. 

Within the test folder, create 3 files named `chmod-XXX.sh`. Each script has file 
permissions set corresponding with their file names (`chmod-777.sh` = `chmod 777`). Below each 
file and permissions can be seen.

```console
$ ls -lart test 
total 24
-rwxrwxrwx   1 user  group   11 May 19 13:15 chmod-777.sh
-rw-rw-rw-   1 user  group   11 May 19 13:16 chmod-666.sh
drwxr-xr-x   5 user  group  160 May 19 13:19 .
-rw-rw-r--   1 user  group   11 May 19 13:19 chmod-664.sh
drwxr-xr-x  10 user  group  320 May 19 13:29 ..
```

Below is the snippet nfpm configuration file of the contents of the package. The test folder 
and files has no extra config for enforcing permissions. 

```yaml
contents:
- src: foo-binary
  dst: /usr/bin/bar
- src: bar-config.conf
  dst: /etc/foo-binary/bar-config.conf
  type: config
- src: test
  dst: /etc/test/scripts
```

The next step is to create a deb package.

```console
$ nfpm package -p deb # Create dep package
using deb packager...
created package: foo_1.0.0_arm64.deb
```

When on a Ubuntu VM, install the foo package which was created

```console
$ sudo dpkg -i foo_1.0.0_arm64.deb # Installing deb package within Ubuntu
Selecting previously unselected package foo.
(Reading database ... 67540 files and directories currently installed.)
Preparing to unpack foo_1.0.0_arm64.deb ...
Unpacking foo (1.0.0) ...
Setting up foo (1.0.0) ...
```

Looking at `/etc/test/scripts` and viewing the permissions. Permissions are passed exactly the same as the source.

```console
$ ls -lart /etc/test/scripts
total 20
-rwxrwxrwx 1 root root   11 May 22 12:15 chmod-777.sh
-rw-rw-rw- 1 root root   11 May 22 12:16 chmod-666.sh
-rw-rw-r-- 1 root root   11 May 22 12:19 chmod-664.sh
drwxr-xr-x 3 root root 4096 May 22 13:00 ..
drwxr-xr-x 2 root root 4096 May 22 13:00 .
```


## Solution
To prevent world-writable files from making it into the packages, add the ability to override the default permissions of packaged files using a umask config option in the packaging spec file. This feature in nfpm would allow applying a global umask across any files being packaged, therefore, with the correct configuration, preventing world-writable files without needing to list permissions on each and every file in the package


### Impact

Vulnerability is https://cwe.mitre.org/data/definitions/276.html
https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

Anyone using nfpm for creating packages and not checking/setting file permissions before packaging could result in bad permissions for files/folders.
