# piccolo SQL Injection via named transaction savepoints

**GHSA**: GHSA-xq59-7jf3-rjc6 | **CVE**: CVE-2023-47128 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-89

**Affected Packages**:
- **piccolo** (pip): < 1.1.1

## Description

### Summary
The handling of named transaction savepoints in all database implementations is vulnerable to [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) as user provided input is passed directly to `connection.execute(...)` via f-strings.

### Details

An excerpt of the Postgres savepoint handling:
```python
    async def savepoint(self, name: t.Optional[str] = None) -> Savepoint:
        name = name or f"savepoint_{self.get_savepoint_id()}"
        await self.connection.execute(f"SAVEPOINT {name}")
        return Savepoint(name=name, transaction=self)
```

In this example, we can see user input is directly passed to `connection.execute` without being properly escaped. 

All implementations of savepoints and savepoint methods directly pass this `name` parameter to `connection.execute` and are vulnerable to this. A non-exhaustive list can be found below:
- Postgres
- - [One](https://github.com/piccolo-orm/piccolo/blob/master/piccolo/engine/postgres.py#L239)
- - [Two](https://github.com/piccolo-orm/piccolo/blob/master/piccolo/engine/postgres.py#L133)
- - [Three](https://github.com/piccolo-orm/piccolo/blob/master/piccolo/engine/postgres.py#L138)
- Sqlite
- - [One](https://github.com/piccolo-orm/piccolo/blob/master/piccolo/engine/sqlite.py#L416)
- - [Two](https://github.com/piccolo-orm/piccolo/blob/master/piccolo/engine/sqlite.py#L313)
- - [Three](https://github.com/piccolo-orm/piccolo/blob/master/piccolo/engine/sqlite.py#L318)

Care should be given to ensuring all strings passed to `connection.execute` are properly escaped, regardless of how end user facing they may be.

Further to this, the [following method](https://github.com/piccolo-orm/piccolo/blob/master/piccolo/engine/postgres.py#L404) also passes user input directly to an execution context however I have been unable to abuse this functionality at the time of writing. This method also has a far lower chance of being exposed to an end user as it relates to database init functionality.

### PoC

The following FastAPI route can be used in conjunction with [sqlmap](https://github.com/sqlmapproject/sqlmap) to easily demonstrate the SQL injection.

```python
DB = ...

@app.get("/test")
async def test(name):
    async with DB.transaction() as transaction:
        await transaction.savepoint(name)
```

##### Steps

1. Create a standard Piccolo application with Postgres as a database backend
2. Add the route shown previously
3. Run your application, making a note of the URL it is served on
4. Install [sqlmap](https://github.com/sqlmapproject/sqlmap)
5. In a terminal, run the following command substituting URL with your applications URL: `sqlmap -u "http://URL/test?name=a" --batch`
6. Observe sqlmap identifying the vulnerability

For sqlmap help, [this usage guide](https://github.com/sqlmapproject/sqlmap/wiki/Usage) may be useful. The following commands may also be helpful to see the impact.

###### Dumping all tables

The `--tables` flag will enumerate all tables accessible from within the exposed database session.

`sqlmap -u "http://URL/test?name=a" --batch --tables`

An example output of this can be seen in the following screenshot.
![Screenshot from 2023-11-06 23-10-30](https://user-images.githubusercontent.com/47520067/280669236-5be9dc0f-4d2c-4bad-a1ba-fc1eb43fdb34.png)


###### OS Shell

The `--os-shell` will drop the user into an OS shell on the underlying system if permissions permit. This can be seen in the attached screenshot which prints the databases current working directory. 
![Screenshot from 2023-11-06 22-43-50](https://user-images.githubusercontent.com/47520067/280668670-0a152589-5f4c-468d-99b9-045226934007.png)


### Impact

While the likelihood of an end developer exposing a savepoints `name` parameter to a user is highly unlikely, it would not be unheard of. If a malicious user was able to abuse this functionality they would have essentially direct access to the database and the ability to modify data to the level of permissions associated with the database user. 

A non exhaustive list of actions possible based on database permissions is:
- Read all data stored in the database, including usernames and password hashes
- Insert arbitrary data into the database, including modifying existing records 
- Gain a shell on the underlying server
