# 技术栈指纹识别参考

## Web 服务器

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

## 编程语言

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

## CMS 识别

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
