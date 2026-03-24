# 敏感文件参考列表

文件包含漏洞利用时的目标文件速查表。

## Linux

```
# 系统信息
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/crontab
/proc/version
/proc/cmdline

# 服务配置
/etc/ssh/sshd_config
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf

# 敏感凭证
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/user/.bash_history
/home/user/.ssh/id_rsa

# /proc 文件系统
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
/proc/self/maps
/proc/self/cwd/index.php

# 日志文件
/var/log/auth.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/mail.log
/var/log/vsftpd.log
```

## Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\Users\Administrator\.ssh\id_rsa
```

## Web 应用配置文件

```
# PHP
index.php, config.php, database.php, db.php, settings.php
.htaccess, .htpasswd, wp-config.php, configuration.php

# Java
WEB-INF/web.xml, WEB-INF/classes/, META-INF/MANIFEST.MF

# Python
settings.py, config.py, app.py, requirements.txt

# Node.js
package.json, .env, config.json
```

## Session 文件路径

```
/tmp/sess_<PHPSESSID>
/var/lib/php/sessions/sess_<PHPSESSID>
/var/lib/php5/sess_<PHPSESSID>
C:\Windows\Temp\sess_<PHPSESSID>
```
