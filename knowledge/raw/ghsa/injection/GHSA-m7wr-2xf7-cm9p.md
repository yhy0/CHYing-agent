# pgx SQL Injection via Line Comment Creation

**GHSA**: GHSA-m7wr-2xf7-cm9p | **CVE**: CVE-2024-27289 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/jackc/pgx** (go): < 4.18.2
- **github.com/jackc/pgx/v4** (go): < 4.18.2

## Description

### Impact

SQL injection can occur when all of the following conditions are met:

1. The non-default simple protocol is used.
2. A placeholder for a numeric value must be immediately preceded by a minus.
3. There must be a second placeholder for a string value after the first placeholder; both
must be on the same line.
4. Both parameter values must be user-controlled.

e.g. 

Simple mode must be enabled:

```go
// connection string includes "prefer_simple_protocol=true"
// or
// directly enabled in code
config.ConnConfig.PreferSimpleProtocol = true
```

Parameterized query:

```sql
SELECT * FROM example WHERE result=-$1 OR name=$2;
```

Parameter values:

`$1` => `-42`
`$2` => `"foo\n 1 AND 1=0 UNION SELECT * FROM secrets; --"`

Resulting query after preparation:

```sql
SELECT * FROM example WHERE result=--42 OR name= 'foo
1 AND 1=0 UNION SELECT * FROM secrets; --';
```

### Patches

The problem is resolved in v4.18.2.

### Workarounds

Do not use the simple protocol or do not place a minus directly before a placeholder.
