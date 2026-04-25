# DB-GPT is vulnerable to SQL Injection attacks from unauthenticated users

**GHSA**: GHSA-qccg-9m4q-xfm6 | **CVE**: CVE-2024-10835 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-89

**Affected Packages**:
- **dbgpt** (pip): < 0.7.1

## Description

In eosphoros-ai/db-gpt version v0.6.0, the web API `POST /api/v1/editor/sql/run` allows execution of arbitrary SQL queries without any access control. This vulnerability can be exploited by attackers to perform Arbitrary File Write using DuckDB SQL, enabling them to write arbitrary files to the victim's file system. This can potentially lead to Remote Code Execution (RCE).
