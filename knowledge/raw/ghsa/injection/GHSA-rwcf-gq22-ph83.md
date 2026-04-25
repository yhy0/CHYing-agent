# IBAX go-ibax vulnerable to SQL injection

**GHSA**: GHSA-rwcf-gq22-ph83 | **CVE**: CVE-2022-3800 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/IBAX-io/go-ibax** (go): < 1.4.2

## Description

A vulnerability, which was classified as critical, has been found in IBAX go-ibax. Affected by this issue is some unknown functionality of the file /api/v2/open/rowsInfo. The manipulation of the argument table_name leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-212636.
