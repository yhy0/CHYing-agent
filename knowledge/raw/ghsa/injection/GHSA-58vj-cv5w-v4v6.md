# Navidrome has Multiple SQL Injections and ORM Leak

**GHSA**: GHSA-58vj-cv5w-v4v6 | **CVE**: CVE-2024-47062 | **Severity**: critical (CVSS 8.8)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/navidrome/navidrome** (go): < 0.53.0

## Description

# Security Advisory: Multiple Vulnerabilities in Navidrome

## Summary

Navidrome automatically adds parameters in the URL to SQL queries. This can be exploited to access information by adding parameters like `password=...` in the URL (ORM Leak).

Furthermore, the names of the parameters are not properly escaped, leading to SQL Injections.

Finally, the username is used in a `LIKE` statement, allowing people to log in with `%` instead of their username.

## Details

### ORM Leak

When adding parameters to the URL, they are automatically included in an SQL `LIKE` statement (depending on the parameter's name). This allows attackers to potentially retrieve arbitrary information.

For example, attackers can use the following request to test whether some encrypted passwords start with `AAA`:

```
GET /api/user?_end=36&_order=DESC&password=AAA%
```

This results in an SQL query like `password LIKE 'AAA%'`, allowing attackers to slowly brute-force passwords. (Also, any reason for using encryption instead of hashing?)

### SQL Injections

When adding parameters to the URL, they are automatically added to an SQL query. The names of the parameters are not properly escaped.

This behavior can be used to inject arbitrary SQL code (SQL Injection), for example:

```
GET /api/album?_end=36&_order=DESC&_sort=recently_added&_start=0&SELECT+*+FROM+USER--=123 HTTP/1.1
```

This is only an example, but you should see an error message in the logs.

### Authentication Weakness

When retrieving the user for authentication, the following code is used:

```go
func (r *userRepository) FindByUsername(username string) (model.User, error) {
    sel := r.newSelect().Columns("").Where(Like{"user_name": username})
    var usr model.User
    err := r.queryOne(sel, &usr)
    return &usr, err
}
```

This relies on a `LIKE` statement and allows users to log in with `%` instead of the legitimate username.

## Proof of Concept (PoC)

See above.

## Impact

These vulnerabilities can be used to leak information and dump the contents of the database.

## Credit

Louis Nyffenegger from PentesterLab
