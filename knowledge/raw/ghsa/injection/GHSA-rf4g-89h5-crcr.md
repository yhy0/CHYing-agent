# melange affected by potential host command execution via license-check YAML mode patch pipeline 

**GHSA**: GHSA-rf4g-89h5-crcr | **CVE**: CVE-2026-25143 | **Severity**: high (CVSS 7.8)

**CWE**: CWE-78

**Affected Packages**:
- **chainguard.dev/melange** (go): >= 0.10.0, < 0.40.3

## Description

An attacker who can influence inputs to the patch pipeline could execute arbitrary shell commands on the build host. The patch pipeline in pkg/build/pipelines/patch.yaml embeds input-derived values (series paths, patch filenames, and numeric parameters) into shell scripts without proper quoting or validation, allowing shell metacharacters to break out of their intended context.                                                                                                                                                               
                                                                                                                                                                                        
The vulnerability affects the built-in patch pipeline which can be invoked through melange build and melange license-check operations. An attacker who can control patch-related inputs (e.g., through pull request-driven CI, build-as-a-service, or by influencing melange configurations) can inject shell metacharacters such as backticks, command substitutions  $(…), semicolons, pipes, or redirections to execute arbitrary commands with the privileges of the melange build process.                                                              

Fix: Fixed in [bd132535](https://github.com/chainguard-dev/melange/commit/bd132535cd9f57d4bd39d9ead0633598941af030) ,  Released in 0.40.3.
                                                                                                                                                                                 
Acknowledgements                                                                                                                                                                      
                                                                                                                                                                                        
melange thanks Oleh Konko (@1seal) from 1seal for discovering and reporting this issue.
