# 网络通信与协议逆向模块

## 适用场景
- C2（Command & Control）通信分析
- TLS/SSL 流量拦截与解密
- 自定义协议逆向
- DNS 隧道检测
- API 端点发现

## 检查清单

```yaml
网络行为发现:
  - [ ] strace -e network 跟踪连接目标（IP/端口）
  - [ ] tcpdump 抓包保存 pcap
  - [ ] /proc/pid/net/tcp 查看连接状态
  - [ ] DNS 查询跟踪（strace + tcpdump port 53）

TLS 流量解密:
  - [ ] SSLKEYLOGFILE 导出会话密钥
  - [ ] openssl s_client 连接获取证书
  - [ ] 证书 CN/SAN 提取真实域名
  - [ ] mitmproxy 中间人（如果证书不验证）
  - [ ] LD_PRELOAD 劫持证书验证（如果自定义验证）

协议分析:
  - [ ] 抓包后分析报文结构（长度/分隔符/magic）
  - [ ] 识别编码方式（plaintext/base64/protobuf/msgpack）
  - [ ] frida hook send/recv 获取明文
  - [ ] 重放请求测试

端点发现:
  - [ ] 字符串搜索 URL/路径
  - [ ] strace 跟踪 DNS 解析
  - [ ] 流量中提取 Host header
  - [ ] JS/配置文件中的 API 路径
```

## 分析流程

### Step 1: 网络行为发现

```bash
# 1. strace 跟踪网络系统调用
strace -f -e trace=network -s 500 ./target 2>&1 | tee /tmp/net_strace.log

# 从 strace 提取关键信息
grep 'connect(' /tmp/net_strace.log          # 连接目标
grep 'bind(' /tmp/net_strace.log             # 监听端口
grep 'sendto\|send(' /tmp/net_strace.log     # 发送数据
grep 'recvfrom\|recv(' /tmp/net_strace.log   # 接收数据
grep 'getaddrinfo' /tmp/net_strace.log       # DNS 解析

# 2. tcpdump 抓包（并行执行）
tcpdump -i any -w /tmp/capture.pcap &
TCPDUMP_PID=$!
./target
sleep 5
kill $TCPDUMP_PID

# 3. 分析 pcap
tcpdump -r /tmp/capture.pcap -nn | head -50               # 概览
tcpdump -r /tmp/capture.pcap -nn -A | head -200            # 含 ASCII payload
tcpdump -r /tmp/capture.pcap -nn 'port 443'                # TLS 流量
tcpdump -r /tmp/capture.pcap -nn 'port 53'                 # DNS 查询

# 4. tshark 深度分析（如果可用）
tshark -r /tmp/capture.pcap -Y 'tcp' -T fields -e ip.dst -e tcp.dstport | sort -u
tshark -r /tmp/capture.pcap -Y 'dns' -T fields -e dns.qry.name | sort -u
tshark -r /tmp/capture.pcap -Y 'http' -T fields -e http.host -e http.request.uri
```

### Step 2: TLS 流量解密

#### 方法 1: SSLKEYLOGFILE（首选）

```bash
# 适用于使用标准 TLS 库（OpenSSL/GnuTLS/NSS/BoringSSL）的程序
# Go 程序默认不支持 SSLKEYLOGFILE，除非代码中显式实现

# 1. 启动抓包
tcpdump -i any -w /tmp/tls_capture.pcap &
TCPDUMP_PID=$!

# 2. 设置密钥日志并运行
SSLKEYLOGFILE=/tmp/sslkeys.log ./target

kill $TCPDUMP_PID

# 3. 检查是否有密钥输出
cat /tmp/sslkeys.log
# 如果非空，说明 SSLKEYLOGFILE 生效

# 4. 用 tshark 解密
tshark -r /tmp/tls_capture.pcap \
    -o tls.keylog_file:/tmp/sslkeys.log \
    -Y 'http' -T fields -e http.host -e http.request.uri -e http.response.code

# 或导出解密后的 HTTP 对象
tshark -r /tmp/tls_capture.pcap \
    -o tls.keylog_file:/tmp/sslkeys.log \
    --export-objects http,/tmp/http_objects/
```

#### 方法 2: openssl s_client 直接连接

```bash
# 获取服务器证书（不需要运行目标程序）
echo | openssl s_client -connect IP:PORT -servername HOSTNAME 2>/dev/null | openssl x509 -text

# 提取证书关键信息
echo | openssl s_client -connect IP:PORT 2>/dev/null | openssl x509 -noout \
    -subject -issuer -dates -ext subjectAltName

# 获取完整证书链
echo | openssl s_client -connect IP:PORT -showcerts 2>/dev/null
```

#### 方法 3: Python 证书提取

```python
import socket, ssl, re

def extract_cert_info(host, port=443):
    """提取 TLS 证书信息"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # 解析证书
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()

                print(f"TLS Version: {version}")
                print(f"Cipher: {cipher}")

                if cert:
                    print(f"Subject: {cert.get('subject')}")
                    print(f"Issuer: {cert.get('issuer')}")
                    print(f"SAN: {cert.get('subjectAltName')}")
                    print(f"Not Before: {cert.get('notBefore')}")
                    print(f"Not After: {cert.get('notAfter')}")

                # 从 DER 中提取可打印字符串（备选）
                strings = re.findall(rb'[\x20-\x7e]{4,}', cert_der)
                print("\nCert strings:")
                for s in strings:
                    decoded = s.decode('latin-1')
                    if any(kw in decoded.lower() for kw in ['com', 'org', 'net', 'aws', 'cloud', 'flag', 'ctf']):
                        print(f"  {decoded}")

                return cert, cert_der, cipher

    except Exception as e:
        print(f"Error: {e}")
        return None, None, None

# 使用
extract_cert_info("3.147.21.228", 443)
```

#### 方法 4: mitmproxy 中间人

```bash
# 适用于不验证证书的程序

# 1. 启动 mitmproxy
mitmproxy --mode transparent -w /tmp/traffic.flow &
# 或 mitmdump（无 UI）
mitmdump --mode transparent -w /tmp/traffic.flow &

# 2. 设置代理环境变量
HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
./target

# 3. 查看捕获的流量
mitmdump -r /tmp/traffic.flow
```

#### 方法 5: LD_PRELOAD 禁用证书验证

```c
// anti_ssl_verify.c — 劫持 SSL 验证相关函数
#define _GNU_SOURCE
#include <dlfcn.h>

// OpenSSL: 禁用证书验证回调
int SSL_CTX_set_verify(void *ctx, int mode, void *callback) {
    typedef int (*real_func)(void *, int, void *);
    real_func orig = (real_func)dlsym(RTLD_NEXT, "SSL_CTX_set_verify");
    return orig(ctx, 0, (void*)0);  // mode=0 = SSL_VERIFY_NONE
}

// OpenSSL: 始终返回验证成功
long SSL_get_verify_result(void *ssl) {
    return 0;  // X509_V_OK
}
```

```bash
gcc -shared -fPIC anti_ssl_verify.c -o /tmp/anti_ssl.so -ldl
LD_PRELOAD=/tmp/anti_ssl.so ./target
```

### Step 3: 自定义协议分析

#### 报文结构识别

```python
#!/usr/bin/env python3
"""分析抓包数据，识别协议结构"""

from scapy.all import rdpcap, TCP, Raw

packets = rdpcap('/tmp/capture.pcap')

for pkt in packets:
    if TCP in pkt and Raw in pkt:
        data = bytes(pkt[Raw])
        src = f"{pkt['IP'].src}:{pkt[TCP].sport}"
        dst = f"{pkt['IP'].dst}:{pkt[TCP].dport}"

        print(f"\n{src} -> {dst} ({len(data)} bytes)")
        print(f"  Hex: {data[:64].hex()}")
        print(f"  ASCII: {data[:64]}")

        # 检测常见编码
        try:
            import base64
            decoded = base64.b64decode(data)
            print(f"  Base64 decoded: {decoded[:64]}")
        except:
            pass

        # 检测 JSON
        if data.startswith(b'{') or data.startswith(b'['):
            print(f"  JSON detected!")

        # 检测 protobuf（以 varint 开头）
        if data[0] & 0x07 in (0, 1, 2, 5):
            print(f"  Possible protobuf (field tag: {data[0]})")
```

#### 请求重放

```python
#!/usr/bin/env python3
"""重放捕获的请求"""
import socket
import ssl

def replay_request(host, port, data, use_tls=True):
    """重放原始请求"""
    sock = socket.create_connection((host, port), timeout=10)

    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)

    sock.send(data)
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break

    sock.close()
    return response

# 使用示例
# data = bytes.fromhex("...")  # 从 pcap 中提取的原始请求
# response = replay_request("target_ip", 443, data)
# print(response)
```

### Step 4: C2 通信分析模式

```yaml
C2 通信分析框架:
  1. 识别通信通道:
     - HTTP/HTTPS (最常见)
     - DNS 隧道
     - 自定义 TCP/UDP
     - WebSocket

  2. 分析通信模式:
     - Beacon 频率（心跳间隔）
     - 数据格式（JSON/protobuf/自定义二进制）
     - 加密方式（TLS/自定义加密层）

  3. 提取关键数据:
     - C2 域名/IP
     - 通信密钥
     - 命令格式
     - 外泄数据内容

  4. 利用方式:
     - 直接 curl/wget C2 端点
     - 伪造 beacon 请求
     - 提取 flag（可能在 C2 响应中）
```

### Step 5: DNS 分析

```bash
# 跟踪 DNS 查询
tcpdump -i any port 53 -nn &
./target

# 提取 DNS 查询域名
tshark -r /tmp/capture.pcap -Y 'dns.qry.name' \
    -T fields -e dns.qry.name | sort -u

# DNS 隧道检测（异常长子域名）
tshark -r /tmp/capture.pcap -Y 'dns.qry.name' \
    -T fields -e dns.qry.name | awk -F. '{if(length($1) > 20) print}'

# DNS TXT 记录可能包含编码数据
dig TXT suspicious-domain.com
```

## 常见 C2 框架特征

```yaml
Cobalt Strike:
  - Beacon 默认端口: 80/443/8443
  - 默认 URI: /submit.php, /activity, /__utm.gif
  - User-Agent 可能异常
  - Cookie 中的 Metadata

Metasploit:
  - Meterpreter 默认通信
  - 特征性握手字节

自定义 C2:
  - 需要逆向分析协议
  - 关注 send/recv 函数的参数
```

## 工具速查

```bash
# 网络跟踪
strace -f -e network -s 500 ./target 2>&1     # 系统调用级
tcpdump -i any -w /tmp/out.pcap                # 抓包
ss -tlnp                                        # 监听端口

# TLS
SSLKEYLOGFILE=/tmp/keys.log ./target           # 导出密钥
openssl s_client -connect IP:PORT              # 证书查看
tshark -r pcap -o tls.keylog_file:keys.log     # 解密

# DNS
tcpdump -i any port 53 -nn                     # DNS 查询
dig TXT domain.com                             # TXT 记录

# 代理
mitmproxy --mode transparent -w out.flow       # 中间人
HTTP_PROXY=http://127.0.0.1:8080 ./target      # 代理
```
