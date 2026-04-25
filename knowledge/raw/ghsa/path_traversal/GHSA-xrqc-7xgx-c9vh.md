#  RCE via ZipSlip and symbolic links in argoproj/argo-workflows

**GHSA**: GHSA-xrqc-7xgx-c9vh | **CVE**: CVE-2025-66626 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-23, CWE-59, CWE-78

**Affected Packages**:
- **github.com/argoproj/argo-workflows/v3** (go): >= 3.7.0, < 3.7.5
- **github.com/argoproj/argo-workflows/v3** (go): < 3.6.14
- **github.com/argoproj/argo-workflows** (go): <= 2.5.3-rc4

## Description

### Summary
The patch deployed against CVE-2025-62156 is ineffective against malicious archives containing symbolic links.

### Details
The untar code that handles symbolic links in archives is unsafe. Concretely, the computation of the link's target and the subsequent check are flawed: 
https://github.com/argoproj/argo-workflows/blob/5291e0b01f94ba864f96f795bb500f2cfc5ad799/workflow/executor/executor.go#L1034-L1037

### PoC
1. Create a malicious archive containing two files: a symbolik link with path "./work/foo" and target "/etc", and a normal text file with path "./work/foo/hostname".
2. Deploy a workflow like the one in https://github.com/argoproj/argo-workflows/security/advisories/GHSA-p84v-gxvw-73pf with the malicious archive mounted at /work/tmp.
3. Submit the workflow and wait for its execution. 
4. Connect to the corresponding pod and observe that the file "/etc/hostname" was altered by the untar operation performed on the malicious archive. The attacker can hence alter arbitrary files in this way. 

### Impact
The attacker can overwrite the file /var/run/argo/argoexec with a script of their choice, which will be executed at the pod's start.
