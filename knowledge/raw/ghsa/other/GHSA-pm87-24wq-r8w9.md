# Apache Airflow Session Fixation vulnerability

**GHSA**: GHSA-pm87-24wq-r8w9 | **CVE**: CVE-2023-40273 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-384

**Affected Packages**:
- **apache-airflow** (pip): < 2.7.0rc2

## Description

The session fixation vulnerability allowed the authenticated user to continue accessing Airflow webserver even after the password of the user has been reset by the admin - up until the expiry of the session of the user. Other than manually cleaning the session database (for database session backend), or changing the secure_key and restarting the webserver, there were no mechanisms to force-logout the user (and all other users with that).

With this fix implemented, when using the database session backend, the existing sessions of the user are invalidated when the password of the user is reset. When using the securecookie session backend, the sessions are NOT invalidated and still require changing the secure key and restarting the webserver (and logging out all other users), but the user resetting the password is informed about it with a flash message warning displayed in the UI. Documentation is also updated explaining this behaviour.

Users of Apache Airflow are advised to upgrade to version 2.7.0 or newer to mitigate the risk associated with this vulnerability.

