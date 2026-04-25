# apko affected by potential unbounded resource consumption in expandapk.ExpandApk on attacker-controlled .apk streams

**GHSA**: GHSA-f4w5-5xv9-85f6 | **CVE**: CVE-2026-25140 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400, CWE-770

**Affected Packages**:
- **chainguard-dev/apko** (go): > 0.14.8, < 1.1.0
- **chainguard.dev/apko** (go): >= 0.14.8, < 1.1.1

## Description

An attacker who controls or compromises an APK repository used by apko could cause resource exhaustion on the build host. The ExpandApk function in pkg/apk/expandapk/expandapk.go expands .apk streams without enforcing decompression limits, allowing a malicious repository to serve a small, highly-compressed .apk that inflates into a large tar stream, consuming excessive disk space and CPU time, causing build failures or denial of service.                                                                                                                       
                                                                                                                                                                                             
**Fix**: Fixed in [2be3903](https://github.com/chainguard-dev/apko/commit/2be3903fe194ad46351840f0569b35f5ac965f09). Released in 1.1.0.
                                                                                                                                                                                             
**Acknowledgements**                                                                                                                                                                            
                                                                                                                                                                                              
apko thanks Oleh Konko (@1seal) from 1seal for discovering and reporting this issue.
