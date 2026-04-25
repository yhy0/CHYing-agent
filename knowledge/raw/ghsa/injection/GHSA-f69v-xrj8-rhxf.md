# org.xwiki.platform:xwiki-platform-rest-server allows SQL injection in query endpoint of REST API

**GHSA**: GHSA-f69v-xrj8-rhxf | **CVE**: CVE-2025-32969 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **org.xwiki.platform:xwiki-platform-rest-server** (maven): >= 1.8, < 15.10.16
- **org.xwiki.platform:xwiki-platform-rest-server** (maven): >= 16.0.0-rc-1, < 16.4.6
- **org.xwiki.platform:xwiki-platform-rest-server** (maven): >= 16.5.0-rc-1, < 16.10.1

## Description

### Impact

It is possible for a remote unauthenticated user to escape from the HQL execution context and perform a blind SQL injection to execute arbitrary SQL statements on the database backend, including when "Prevent unregistered users from viewing pages, regardless of the page rights" and "Prevent unregistered users from editing pages, regardless of the page rights" options are enabled.

Depending on the used database backend, the attacker may be able to not only obtain confidential information such as password hashes from the database, but also execute UPDATE/INSERT/DELETE queries.

The vulnerability may be tested in a default installation of XWIki Standard Flavor, including using the official Docker containers.

An example query, which leads to SQL injection with MySQL/MariaDB backend is shown below:

```
time curl "http://127.0.0.1:8080/rest/wikis/xwiki/query?q=where%20doc.name=length('a')*org.apache.logging.log4j.util.Chars.SPACE%20or%201%3C%3E%271%5C%27%27%20union%20select%201,2,3,sleep(10)%20%23%27&type=hql&distinct=0"
```

When executed, the response from the server will come after a delay of 10 extra seconds, indicating successful execution of the injected SQL statement.

An example of a query for the PostgreSQL database backend is shown below:

```
curl "https://127.0.0.1:8080/rest/wikis/xwiki/query?q=where%20%24%24='%24%24=concat(%20chr(%2061%20),(chr(%2039%20))%20)%20;select%201%20--%20comment'&type=hql&distinct=0"
```

Both requests employ database backend dependent techniques of breaking out of HQL query context, described, for example, here: https://www.sonarsource.com/blog/exploiting-hibernate-injections.

### Patches

This has been patched in 16.10.1, 16.4.6 and 15.10.16.

### Workarounds

There is no known workaround, other than upgrading XWiki.

### References

https://jira.xwiki.org/browse/XWIKI-22691

### For more information

If you have any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email us at [Security Mailing List](mailto:security@xwiki.org)

### Attribution

Sergey Anufrienko from Kaspersky ICS-CERT vulnerability research team reported this vulnerability.
