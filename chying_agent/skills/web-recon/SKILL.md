---
name: web-recon
description: "对目标 Web 应用执行系统性信息收集与攻击面发现，包括 HTTP 头分析、目录扫描、端口扫描、技术栈指纹识别和参数发现。当开始渗透测试、需要了解目标架构、发现隐藏路径或识别潜在漏洞入口时使用。"
allowed-tools: Bash, Read, Write
---

# Web 应用侦察 (Web Reconnaissance)

系统性地收集目标信息，发现攻击面和潜在漏洞点。

> **参考文件**: 完整词表见 [WORDLISTS.md](./WORDLISTS.md)，指纹库见 [FINGERPRINTS.md](./FINGERPRINTS.md)。

## 快速启动

对新目标执行以下 4 步即可完成基础侦察：

```bash
# 1. HTTP 头 + robots.txt（判断服务器类型与禁止路径）
curl -sI http://TARGET && curl -s http://TARGET/robots.txt

# 2. 技术栈识别
whatweb http://TARGET

# 3. 目录扫描（发现隐藏路径）
dirsearch -u http://TARGET -e php,html,js,txt -q

# 4. 快速端口扫描（发现其他服务）
nmap -F TARGET_HOST
```

## 侦察工作流

```
开始
 │
 ├─► 步骤1: 基础信息收集 (HTTP头、robots.txt、sitemap)
 │     │
 │     ├─ ✅ 正常响应 → 记录服务器类型、头信息 → 继续
 │     └─ ⚠️ 被拦截/403 → 检查WAF → 见「WAF与限速处理」
 │
 ├─► 步骤2: 技术栈识别 (whatweb、响应头、Cookie)
 │     │
 │     └─ 📋 验证点: 确认已识别 服务器/语言/框架 至少2项
 │
 ├─► 步骤3: 目录扫描 (dirsearch/gobuster/ffuf)
 │     │
 │     ├─ ✅ 发现路径 → 逐一访问验证，排除误报
 │     └─ ⚠️ 大量429/403 → 降低速率或切换UA → 见「WAF与限速处理」
 │
 ├─► 步骤4: 敏感文件检查 (.git、.env、备份文件)
 │     │
 │     └─ 📋 验证点: 确认已检查 WORDLISTS.md 中所有关键敏感文件
 │
 ├─► 步骤5: 端口扫描与服务识别
 │     │
 │     └─ 📋 验证点: 确认已识别所有开放端口及其服务版本
 │
 ├─► 步骤6: 参数发现与功能点识别
 │     │
 │     └─ 📋 验证点: 记录所有发现的参数，标注高风险参数(file/cmd/url类)
 │
 └─► 输出侦察报告，为后续攻击阶段提供情报
```

## 步骤1: 基础信息收集

```bash
# 获取 HTTP 头（分析 Server、X-Powered-By、安全头）
curl -sI http://target.com

# 获取完整响应（观察页面结构、注释、隐藏表单）
curl -sv http://target.com 2>&1

# 检查 robots.txt（发现禁止爬取的敏感路径）
curl -s http://target.com/robots.txt

# 检查 sitemap.xml（发现站点结构）
curl -s http://target.com/sitemap.xml

# 检查版本控制泄露
curl -sI http://target.com/.git/config
curl -sI http://target.com/.env
```

**验证**: 确认收到响应（非超时），记录 Server 头和状态码。若返回 403/拦截页面，见下方 WAF 处理。

## 步骤2: 技术栈识别

```bash
# 使用 whatweb 自动识别
whatweb http://target.com

# 手动检查关键指标：
# - Server 头 → 服务器类型（见 FINGERPRINTS.md）
# - X-Powered-By → 编程语言
# - Cookie 名称 → PHPSESSID(PHP) / JSESSIONID(Java) / ASP.NET_SessionId(.NET)
# - 默认错误页面 → 框架/CMS 特征
# - 文件扩展名 → .php / .jsp / .aspx
```

**验证**: 至少确认 2 项：服务器类型、编程语言、框架/CMS。若无法确认，尝试触发错误页面（访问不存在的路径）获取更多信息。

## 步骤3: 目录与路径扫描

```bash
# dirsearch（推荐，内置优质词表）
dirsearch -u http://target.com -e php,html,js,txt -q

# gobuster（自定义词表）
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# ffuf（高性能模糊测试）
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403

# 递归扫描（深入子目录）
dirsearch -u http://target.com -e php,html -r --recursion-depth=2
```

**验证**: 对每个发现的路径手动访问确认，排除软 404 误报（对比默认 404 页面大小）。

## 步骤4: 敏感文件检查

参照 [WORDLISTS.md](./WORDLISTS.md) 中的完整敏感文件列表，重点检查：

```bash
# 版本控制泄露（可获取源代码）
curl -sI http://target.com/.git/config
curl -sI http://target.com/.svn/entries

# 环境配置泄露（可获取密钥/密码）
curl -sI http://target.com/.env
curl -sI http://target.com/config.php.bak
curl -sI http://target.com/web.config

# 备份文件
curl -sI http://target.com/backup.zip
curl -sI http://target.com/backup.sql
```

**验证**: 对返回 200 的文件下载内容确认，非空且包含有效数据。

## 步骤5: 端口扫描

```bash
# 快速扫描（常见端口）
nmap -F target.com

# 全端口扫描（耗时但全面）
nmap -p- --min-rate=1000 target.com

# 服务版本检测（针对已发现端口）
nmap -sV -sC -p 80,443,8080,3306 target.com
```

**验证**: 记录所有开放端口及服务名称/版本，特别关注非标准端口上的 Web 服务。

## 步骤6: 参数发现

```bash
# arjun 自动参数发现
arjun -u http://target.com/page

# paramspider 从存档中提取参数
python3 paramspider.py -d target.com

# 手动测试高风险参数（参照 WORDLISTS.md 中的参数列表）
curl -s "http://target.com/page?id=1"
curl -s "http://target.com/page?file=/etc/passwd"
curl -s "http://target.com/page?url=http://127.0.0.1"
```

**验证**: 标注每个参数的潜在漏洞类型（SQLi、LFI、SSRF、RCE）。

## WAF 与限速处理

当侦察过程中遇到拦截或限速时，按以下策略处理：

| 症状 | 判断 | 应对措施 |
|------|------|----------|
| 持续 403 + 特征拦截页面 | WAF 拦截 | 切换 User-Agent、降低请求频率、使用 `--random-agent` |
| 大量 429 Too Many Requests | 速率限制 | 添加 `--delay=1` 或 `-rate 10`，分批扫描 |
| 连接重置/超时 | IP 封禁 | 暂停扫描，等待解封或切换出口 IP |
| 所有路径返回相同内容 | 软 404 / 默认页 | 使用 `-fs` 过滤相同大小的响应 |

```bash
# WAF 绕过示例
dirsearch -u http://target.com -e php --random-agent --delay=1

# ffuf 过滤误报（按响应大小）
ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 1234

# gobuster 限速
gobuster dir -u http://target.com -w wordlist.txt --delay 500ms
```

## 自动化侦察脚本

```bash
#!/bin/bash
TARGET=$1
HOST=$(echo $TARGET | sed 's|http[s]*://||' | cut -d'/' -f1)

echo "[*] === 基础信息收集 ==="
curl -sI $TARGET
echo ""
curl -s $TARGET/robots.txt
echo ""

echo "[*] === 技术栈识别 ==="
whatweb $TARGET
echo ""

echo "[*] === 目录扫描 ==="
dirsearch -u $TARGET -e php,html,js,txt -q
echo ""

echo "[*] === 端口扫描 ==="
nmap -F $HOST
```

## 最佳实践

1. **先轻后重**: 先用被动方式（HTTP 头、robots.txt）收集信息，再进行主动扫描
2. **验证每一步**: 每个阶段完成后确认结果有效，避免在误报上浪费时间
3. **注意隐蔽**: 控制扫描速率，避免触发 WAF/IDS 告警
4. **全面记录**: 记录所有发现（端口、路径、参数、技术栈），为后续攻击提供情报
5. **关注非标准**: 非标准端口、自定义 404、异常头信息往往是突破口
