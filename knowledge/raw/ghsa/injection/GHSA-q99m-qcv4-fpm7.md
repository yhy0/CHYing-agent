# Grafana Command Injection And Local File Inclusion Via Sql Expressions

**GHSA**: GHSA-q99m-qcv4-fpm7 | **CVE**: CVE-2024-9264 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-77, CWE-94

**Affected Packages**:
- **github.com/grafana/grafana** (go): >= 11.0.0, <= 11.0.6
- **github.com/grafana/grafana** (go): >= 11.1.0, <= 11.1.7
- **github.com/grafana/grafana** (go): >= 11.2.0, <= 11.2.2

## Description

The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.
