# Gogs allows deletion of internal files which leads to remote command execution

**GHSA**: GHSA-wj44-9vcg-wjq7 | **CVE**: CVE-2024-56731 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-552

**Affected Packages**:
- **gogs.io/gogs** (go): <= 0.13.2

## Description

### Summary
Due to the insufficient patch for the CVE-2024-39931, it's still possible to delete files under the `.git` directory and achieve remote command execution.

### Details
In the patch for CVE-2024-39931, the following check is added:
https://github.com/gogs/gogs/commit/77a4a945ae9a87f77e392e9066b560edb71b5de9

```diff
+	// 🚨 SECURITY: Prevent uploading files into the ".git" directory
+	if isRepositoryGitPath(opts.TreePath) {
+		return errors.Errorf("bad tree path %q", opts.TreePath)
+	}
```


While the above code snippet checks if the specified path is a `.git` directory, there are no checks for symbolic links in the later steps. So, by creating a symbolic link that points to the `.git` directory, an attacker can still delete arbitrary files in the `.git` directory and achieve remote command execution.

### Impact
Unprivileged user accounts can execute arbitrary commands on the Gogs instance with the privileges of the account specified by `RUN_USER` in the configuration. It allows attackers to access and alter any users' code hosted on the same instance.
