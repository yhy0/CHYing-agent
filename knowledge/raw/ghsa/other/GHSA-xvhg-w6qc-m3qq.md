# Yaklang Plugin's Fuzztag Component Allows Unauthorized Local File Reading

**GHSA**: GHSA-xvhg-w6qc-m3qq | **CVE**: CVE-2023-40023 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-200

**Affected Packages**:
- **github.com/yaklang/yaklang** (go): < 1.2.4-sp2

## Description

### Impact

The Yak Engine has been found to contain a local file inclusion (LFI) vulnerability. This vulnerability allows attackers to include files from the server's local file system through the web application. When exploited, this can lead to the unintended exposure of sensitive data, potential remote code execution, or other security breaches. Users utilizing versions of the Yak Engine prior to 1.2.4-sp1 are impacted.

### Patches

The vulnerability has been addressed and patched. Users are advised to upgrade to Yak Engine version 1.2.4-sp1 immediately. The patch can be viewed and reviewed at this PR: [https://github.com/yaklang/yaklang/pull/295](https://github.com/yaklang/yaklang/pull/295)，[https://github.com/yaklang/yaklang/pull/296](https://github.com/yaklang/yaklang/pull/296)

### Workarounds

Currently, the most effective solution is to upgrade to the patched version of Yak Engine (1.2.4-sp1). Users are also advised to avoid exposing vulnerable versions to untrusted input and to closely monitor any unexpected server behavior until they can upgrade.

### References

For more details on the vulnerability and the corresponding patch, please visit the following link:
- [PR addressing the LFI vulnerability in Yak Engine](https://github.com/yaklang/yaklang/pull/295)
- [disable default file fuzztag in fuzz.Pool](https://github.com/yaklang/yaklang/pull/296)
- [利用yakit功能特性溯源攻击者](https://mp.weixin.qq.com/s?__biz=Mzg5ODE3NTU1OQ==&mid=2247484236&idx=1&sn=ef0c14a89721800b2311d0e487388399)
