# gosqljson SQL Injection vulnerability

**GHSA**: GHSA-g7mw-9pf9-p2pm | **CVE**: CVE-2014-125064 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/elgs/gosqljson** (go): < 0.0.0-20220916234230-750f26ee23c7

## Description

A vulnerability, which was classified as critical, has been found in elgs gosqljson. This issue affects the function `QueryDbToArray/QueryDbToMap/ExecDb` of the file `gosqljson.go`. The manipulation of the argument sqlStatement leads to sql injection. The name of the patch is 2740b331546cb88eb61771df4c07d389e9f0363a. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217631.
