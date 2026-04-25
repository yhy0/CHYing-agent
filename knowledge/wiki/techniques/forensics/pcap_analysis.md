---
category: forensics
tags: [pcap, wireshark, tshark, scapy, network_forensics, packet_capture, dns_exfiltration, tls_decryption, usb_hid, wifi_cracking, 流量分析, 数据包取证, 网络取证]
triggers: [pcap, pcapng, packet capture, wireshark, tshark, network forensics, traffic analysis, dns exfiltration, tls decrypt, usb keyboard, wifi handshake, 流量分析, 抓包, 数据包]
related: [memory_forensics, steganography]
---

# 网络流量分析 (PCAP Forensics)

## 什么时候用

拿到 `.pcap` / `.pcapng` 文件，需要从网络流量中提取 flag、凭据、隐藏数据。CTF 中最常见的 forensics 题型之一。

## 前提条件

- **有抓包文件**：`.pcap` / `.pcapng`（损坏时先用 `pcapfix -d` 修复）
- **tshark/Wireshark 可用**：命令行分析首选 tshark
- **scapy（可选）**：需要自定义协议解析或脚本化提取时

## 攻击步骤

### 1. 初始分诊：了解流量全貌

```bash
# 协议分层统计 — 快速了解有哪些协议
tshark -r capture.pcap -q -z io,phs

# IP 会话统计 — 找出主要通信对
tshark -r capture.pcap -q -z conv,ip

# 端点统计
tshark -r capture.pcap -q -z endpoints,tcp

# 直接搜 flag 字符串（最快的 first blood 尝试）
tshark -r capture.pcap -Y "frame contains \"flag\"" -T fields -e data.text
```

### 2. HTTP 提取：文件、POST 数据、凭据

```bash
# 列出所有 HTTP 请求
tshark -r capture.pcap -Y "http.request" \
  -T fields -e http.request.method -e http.host -e http.request.uri

# 一键导出所有 HTTP 传输的文件
tshark -r capture.pcap --export-objects http,/tmp/http_objects
ls -la /tmp/http_objects/

# 提取 POST 表单数据（登录凭据等）
tshark -r capture.pcap -Y "http.request.method==POST" \
  -T fields -e http.file_data

# 跟踪特定 TCP 流（文本格式）
tshark -r capture.pcap -q -z "follow,tcp,ascii,0"
```

### 3. DNS 分析：渗出检测与隧道

```bash
# DNS 查询统计
tshark -r capture.pcap -Y "dns.qr==0" \
  -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -20

# DNS TXT 记录（常藏 flag）
tshark -r capture.pcap -Y "dns.txt" -T fields -e dns.txt

# DNS 渗出提取 — 子域名拼接
tshark -r capture.pcap -Y "dns.qr==0" -T fields -e dns.qry.name | \
  grep "suspect.domain" | sed 's/.suspect.domain.//g'
```

**Python scapy 提取 DNS 隧道数据：**
```python
from scapy.all import rdpcap, DNSQR, DNSRR

packets = rdpcap('capture.pcap')
data = b''
prev = None
for pkt in packets:
    if pkt.haslayer(DNSQR) and not pkt.haslayer(DNSRR):
        qname = pkt[DNSQR].qname.decode().rstrip('.')
        labels = qname.replace('.evil.com', '').split('.')
        chunk = bytes.fromhex(''.join(labels))
        if chunk != prev:  # 去重重传
            data += chunk
            prev = chunk
# data 可能是 PNG/ZIP 等文件
with open('exfiltrated.bin', 'wb') as f:
    f.write(data)
```

### 4. TLS/SSL 解密

```bash
# 方法 1：keylog 文件（题目提供 sslkeys.log）
tshark -r capture.pcap -o "tls.keylog_file:sslkeys.log" -Y http

# 方法 2：RSA 私钥（仅限 RSA 密钥交换，非 ECDHE/DHE）
tshark -r capture.pcap -o "tls.keys_list:127.0.0.1,443,http,server.key" -Y http

# 方法 3：弱 RSA — 从证书提取公钥并分解
tshark -r capture.pcap -Y "tls.handshake.type==11" \
  -T fields -e tls.handshake.certificate | head -1
# 用 rsatool 由 p, q 生成私钥后导入 Wireshark
```

### 5. USB HID 键盘提取

```bash
# 提取 HID 报告（8 字节键盘数据）
tshark -r usb.pcap -Y 'usb.capdata && usb.data_len == 8' \
  -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
```

```python
import sys
HID_MAP = {
    0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',
    0x0b:'h',0x0c:'i',0x0d:'j',0x0e:'k',0x0f:'l',0x10:'m',0x11:'n',
    0x12:'o',0x13:'p',0x14:'q',0x15:'r',0x16:'s',0x17:'t',0x18:'u',
    0x19:'v',0x1a:'w',0x1b:'x',0x1c:'y',0x1d:'z',0x1e:'1',0x1f:'2',
    0x20:'3',0x21:'4',0x22:'5',0x23:'6',0x24:'7',0x25:'8',0x26:'9',
    0x27:'0',0x28:'\n',0x2c:' ',0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',
}
SHIFT = {k: v.upper() if v.isalpha() else v for k, v in HID_MAP.items()}
SHIFT.update({0x1e:'!',0x1f:'@',0x20:'#',0x21:'$',0x22:'%',0x23:'^',
              0x24:'&',0x25:'*',0x26:'(',0x27:')',0x2d:'_',0x2e:'+'})

for line in sys.stdin:
    raw = line.strip().replace(':','')
    if len(raw) != 16: continue
    mod, key = int(raw[0:2],16), int(raw[4:6],16)
    if key == 0: continue
    m = SHIFT if mod & 0x22 else HID_MAP
    sys.stdout.write(m.get(key, '?'))
```

### 6. WiFi：WPA 握手破解

```bash
# 识别加密 WiFi 网络
aircrack-ng capture.pcapng

# 破解 WPA/WPA2
aircrack-ng -a 2 -w rockyou.txt capture.pcapng

# 用恢复的密钥解密流量
airdecap-ng -p "passphrase" -e "SSID" capture.pcapng
wireshark capture-dec.pcapng
```

### 7. CTF 常见模式速查

| 模式 | 检查方法 |
|------|----------|
| flag 在 HTTP 响应体 | `tshark --export-objects http,/tmp/out` |
| flag 在 DNS TXT 记录 | `tshark -Y "dns.txt" -T fields -e dns.txt` |
| TCP 流重组 | `tshark -q -z "follow,tcp,ascii,N"` |
| DNS 子域渗出 | 提取 qname 拼接 hex/base32 |
| TCP flag 隐蔽通道 | 6 bit flags → base64 字符 |
| ICMP payload | `tshark -Y "icmp.type==8" -T fields -e data` |
| 数据包间隔编码 | 计算时间差 → 二值化为 0/1 |

## 常见坑

- **损坏的 PCAP**：先跑 `pcapfix -d capture.pcap`，修复后再分析。很多题故意损坏文件头。
- **tshark 版本差异**：旧版用 `ssl.*` 字段，新版改为 `tls.*`。`--export-objects` 在旧版可能不支持。
- **DNS 重传导致数据重复**：提取 DNS 隧道时必须去重（比较相邻 chunk），否则拼出的文件会损坏。
- **多网卡 PCAP**：大 PCAP 里信号可能只在某个 interface 上。用 `tshark -q -z io,phs` 按接口统计，找包最少的那个。
- **USB HID 字段缺失**：如果 Wireshark 没解析 `usbhid.*`，说明没抓到 HID 报告描述符。回退到 `usb.capdata` 手工解码。
- **WiFi 多次换密码**：解密后在明文流量里找下一段的密码提示，需要多轮 `airdecap-ng`。

## 变体

### 隐蔽通道型
- **TCP Flag 通道**：6 bit TCP flags 映射 base64 字符（FIN+SYN 等异常组合是信号）
- **ICMP 载荷**：数据藏在 echo request payload 中，可能经过字节旋转 + base64
- **数据包间隔编码**：相同包的时间间隔二值化为 bit 流

### 特殊协议型
- **SMB3 加密**：提取 NTLMv2 hash → hashcat 破解 → 推导会话密钥 → AES-GCM 解密
- **dnscat2 隧道**：子域名 hex 编码 + 9 字节协议头需剥离
- **5G/NR 协议**：Wireshark 启用 NAS-5GS 解析器

## 相关技术

- [[memory_forensics]] — 内存 dump 中提取 TLS 密钥用于解密 PCAP
- [[steganography]] — 流量中提取的文件可能还需隐写分析
