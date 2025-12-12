---
name: web-recon
description: Web 应用信息收集与侦察。当开始渗透测试、需要了解目标架构、发现攻击面时使用。包括目录扫描、端口扫描、指纹识别。
allowed-tools: Bash, Read, Write
---

# Web 应用侦察 (Web Reconnaissance)

系统性地收集目标信息，发现攻击面和潜在漏洞点。

## 侦察流程

### 1. 基础信息收集

```bash
# 获取 HTTP 头
curl -I http://target.com

# 获取完整响应
curl -v http://target.com

# 检查 robots.txt
curl http://target.com/robots.txt

# 检查 sitemap.xml
curl http://target.com/sitemap.xml

# 检查常见文件
curl http://target.com/.git/config
curl http://target.com/.env
curl http://target.com/backup.zip
curl http://target.com/config.php.bak
```

### 2. 目录扫描

```bash
# 使用 dirsearch
dirsearch -u http://target.com -e php,html,js,txt

# 使用 gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# 使用 ffuf
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# 递归扫描
dirsearch -u http://target.com -e php,html -r
```

### 3. 端口扫描

```bash
# 快速扫描
nmap -F target.com

# 全端口扫描
nmap -p- target.com

# 服务版本检测
nmap -sV -p 80,443,8080 target.com

# 脚本扫描
nmap -sC -sV target.com
```

### 4. 技术栈识别

```bash
# 使用 whatweb
whatweb http://target.com

# 使用 wappalyzer (浏览器插件)

# 手动检查
# - Server 头
# - X-Powered-By 头
# - Cookie 名称 (PHPSESSID, JSESSIONID, ASP.NET_SessionId)
# - 错误页面
# - 文件扩展名
```

## 常见目录和文件

### 敏感文件

```
# 配置文件
.env
.env.local
.env.production
config.php
config.yml
settings.py
database.yml
wp-config.php
web.config
appsettings.json

# 备份文件
backup.zip
backup.tar.gz
backup.sql
db.sql
database.sql
*.bak
*.old
*.orig
*.swp
*~

# 版本控制
.git/config
.git/HEAD
.svn/entries
.hg/
CVS/

# 日志文件
access.log
error.log
debug.log
*.log

# 其他
.htaccess
.htpasswd
crossdomain.xml
clientaccesspolicy.xml
```

### 常见目录

```
# 管理后台
/admin
/administrator
/admin.php
/login
/wp-admin
/manager
/console
/dashboard

# API
/api
/api/v1
/api/v2
/graphql
/swagger
/swagger-ui
/api-docs

# 开发/调试
/debug
/test
/dev
/staging
/phpinfo.php
/info.php

# 上传目录
/upload
/uploads
/files
/images
/media
/attachments

# 备份目录
/backup
/backups
/bak
/old
/temp
/tmp
```

### 常见参数

```
# 文件操作
file=
path=
page=
template=
include=
doc=
document=
folder=
root=
pg=

# 数据库查询
id=
user=
name=
search=
query=
q=
s=
keyword=
cat=
category=
sort=
order=

# 重定向
url=
redirect=
next=
return=
returnUrl=
goto=
link=
target=
dest=
destination=
rurl=
redirect_uri=
continue=

# 命令执行
cmd=
exec=
command=
execute=
ping=
query=
jump=
code=
reg=
do=
func=
arg=
option=
load=
process=
step=
read=
feature=
exe=
module=
payload=
run=
print=
```

## 指纹识别

### Web 服务器

```
# Apache
Server: Apache/2.4.x
# 特征: .htaccess, mod_rewrite

# Nginx
Server: nginx/1.x.x
# 特征: 默认错误页面

# IIS
Server: Microsoft-IIS/10.0
# 特征: .aspx, web.config

# Tomcat
Server: Apache-Coyote/1.1
# 特征: /manager, .jsp
```

### 编程语言

```
# PHP
X-Powered-By: PHP/7.x
Cookie: PHPSESSID
扩展名: .php, .php3, .php5, .phtml

# Java
Cookie: JSESSIONID
扩展名: .jsp, .do, .action
特征: Struts, Spring

# Python
扩展名: .py
特征: Django, Flask

# ASP.NET
X-Powered-By: ASP.NET
Cookie: ASP.NET_SessionId
扩展名: .aspx, .ashx, .asmx

# Node.js
X-Powered-By: Express
特征: package.json
```

### CMS 识别

```
# WordPress
/wp-admin
/wp-content
/wp-includes
/xmlrpc.php
meta generator="WordPress"

# Drupal
/sites/default
/misc/drupal.js
X-Generator: Drupal

# Joomla
/administrator
/components
/modules
meta generator="Joomla"

# Laravel
Cookie: laravel_session
/storage
/.env
```

## 自动化脚本

### 快速侦察脚本

```bash
#!/bin/bash
TARGET=$1

echo "[*] 基础信息收集..."
curl -sI $TARGET
curl -s $TARGET/robots.txt
curl -s $TARGET/sitemap.xml

echo "[*] 目录扫描..."
dirsearch -u $TARGET -e php,html,js,txt -q

echo "[*] 技术栈识别..."
whatweb $TARGET

echo "[*] 端口扫描..."
nmap -F $(echo $TARGET | sed 's|http[s]*://||' | cut -d'/' -f1)
```

### 参数发现

```bash
# 使用 arjun
arjun -u http://target.com/page

# 使用 paramspider
python3 paramspider.py -d target.com

# 手动测试
curl "http://target.com/page?id=1"
curl "http://target.com/page?file=test"
curl "http://target.com/page?cmd=test"
```

## 最佳实践

1. 先收集基础信息（HTTP 头、robots.txt）
2. 识别技术栈（服务器、语言、框架）
3. 目录扫描发现隐藏路径
4. 检查敏感文件（.git、.env、备份）
5. 识别参数和功能点
6. 端口扫描发现其他服务
7. 记录所有发现，为后续攻击做准备
8. 注意 WAF 和速率限制
