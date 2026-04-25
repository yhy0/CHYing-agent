---
category: crypto
tags: [hash_extension, length_extension, md5, sha1, sha256, merkle_damgard, hashpump, hashpumpy, mac_bypass, crc32, hmac, 哈希扩展, 长度扩展, 消息认证码]
triggers: [hash extension, length extension, md5 secret, sha1 secret, sha256 secret, hash(secret+msg), mac verification, hashpump, merkle damgard, H(key||msg), secret prefix, 哈希扩展, 签名绕过, crc32 forgery]
related: [rsa_basic, aes_ecb, padding_oracle]
---

# 哈希长度扩展攻击

## 什么时候用

服务端使用 `H(secret || message)` 作为 MAC（消息认证码），且哈希算法基于 Merkle-Damgard 构造（MD5、SHA-1、SHA-256）。攻击者已知合法的 hash 值和 message，可以在不知道 secret 的情况下构造 `H(secret || message || padding || extension)` 的合法 hash。

## 前提条件

- **MAC 构造为 `H(secret || msg)`**：secret 在前、用户数据在后
- **哈希算法基于 Merkle-Damgard**：MD5、SHA-1、SHA-256 均可；SHA-3（Keccak sponge）不可
- **已知一个合法的 (message, hash) 对**
- **已知或可爆破 secret 长度**（通常 8-32 字节，逐一尝试）
- **服务端接受带有填充字节的扩展消息**
- ⚠️ HMAC（`H(K XOR opad || H(K XOR ipad || msg))`）**不受影响**

## 攻击步骤

### 1. 理解 Merkle-Damgard 构造

```
IV → [Block 1] → state1 → [Block 2] → state2 → ... → [Final] → hash
```

关键洞察：**hash 输出就是最后一个块处理后的内部状态**。知道 hash 值就知道内部状态，可以从这个状态继续 hash 新数据。

### 2. 使用 hashpumpy 自动攻击

```python
# pip install hashpumpy
import hashpumpy

# 已知信息
original_hash = 'e3b0c44298fc1c149afbf4c8996fb924'
original_data = b'user=guest'
append_data = b'&admin=true'
secret_length = 16  # secret 长度（已知或爆破）

# 生成伪造的 hash 和 data
new_hash, new_data = hashpumpy.hashpump(
    original_hash,
    original_data,
    append_data,
    secret_length
)
# new_data 包含: original_data + MD padding + append_data
# new_hash 是对应的合法 hash
print(f"New hash: {new_hash}")
print(f"New data: {new_data}")
```

### 3. 爆破 secret 长度

secret 长度未知时遍历常见范围：

```python
import hashpumpy
import requests

original_hash = 'a1b2c3d4...'
original_data = b'user=guest'
append_data = b'&admin=true'

for key_len in range(1, 33):
    new_hash, new_data = hashpumpy.hashpump(
        original_hash, original_data, append_data, key_len
    )
    # 提交给服务端验证
    resp = requests.get(
        'http://target/verify',
        params={'data': new_data, 'sig': new_hash}
    )
    if 'success' in resp.text.lower() or resp.status_code == 200:
        print(f"[+] Secret length = {key_len}")
        print(f"[+] Forged data: {new_data}")
        print(f"[+] Forged hash: {new_hash}")
        break
```

### 4. 手动实现（无 hashpumpy 时）

```python
import struct

def md5_padding(msg_len):
    """计算 MD5 的 padding 字节"""
    bit_len = msg_len * 8
    pad = b'\x80'
    pad += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack('<Q', bit_len)  # MD5 = little-endian
    return pad

def sha256_padding(msg_len):
    """计算 SHA-256 的 padding 字节"""
    bit_len = msg_len * 8
    pad = b'\x80'
    pad += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack('>Q', bit_len)  # SHA = big-endian
    return pad

# 使用 hlextend 库设置内部状态继续 hash
# pip install hlextend
import hlextend

sha = hlextend.new('sha256')
new_data = sha.extend(
    b'&admin=true',      # 要追加的数据
    b'user=guest',        # 原始数据
    16,                   # secret 长度
    'e3b0c44298fc1c149afbf4c8996fb924...'  # 原始 hash
)
new_hash = sha.hexdigest()
```

### 5. HashPump 命令行工具

```bash
# 安装: apt install hashpump  或  brew install hashpump
hashpump \
  --keylength 16 \
  --signature 'e3b0c44298fc1c149afbf4c8996fb924' \
  --data 'user=guest' \
  --additional '&admin=true'

# 输出:
# new_signature: a8f5f167f44f4964e6c998dee827110c
# new_string: user=guest\x80\x00...\x00\xa0\x00...&admin=true
```

## 常见坑

- **URL 编码填充字节**：new_data 包含 `\x80\x00...` 等不可打印字节。HTTP 提交时需要 URL encode（`%80%00...`），不能直接当字符串传。Python `requests` 对 bytes 参数自动处理，但手动拼 URL 时要用 `%xx`。
- **secret 在后面的构造不可攻击**：`H(msg || secret)` 无法扩展（secret 的 padding 在最后，攻击者不知道 secret）。只有 `H(secret || msg)` 可攻击。
- **HMAC 不受影响**：`HMAC(K, msg) = H((K^opad) || H((K^ipad) || msg))` 的双层结构防止了长度扩展。
- **SHA-3/BLAKE2 不受影响**：基于 sponge 构造，输出不等于内部状态，无法扩展。
- **secret 长度对齐**：填充计算依赖准确的 secret 长度。如果不确定就从 1 爆到 64，通常 CTF 里是 8-32。
- **字节序问题**：MD5 用 little-endian 存储长度，SHA 系列用 big-endian。手动实现时搞反字节序会导致状态恢复错误。
- **hashpumpy 安装失败**：需要 C 编译器。Docker 里先 `apt install build-essential`。备选：`pip install hlextend`。
- **null 字节截断**：padding 里有 `\x00`，某些 web 框架（PHP）会截断。可能需要 base64 编码传输。

## 变体

### CRC32 伪造
CRC32 是线性的，可以在任意数据后追加 4 字节使 CRC32 值等于目标值。任何使用 CRC32 做 MAC 的协议都可伪造：

```python
import binascii

def crc32_forge_bruteforce(data, target_crc, charset=range(256)):
    """暴力搜索 4 字节后缀使 CRC32 匹配目标"""
    for b1 in charset:
        for b2 in charset:
            prefix = data + bytes([b1, b2])
            partial = binascii.crc32(prefix) & 0xFFFFFFFF
            for b3 in charset:
                for b4 in charset:
                    if binascii.crc32(prefix + bytes([b3, b4])) & 0xFFFFFFFF == target_crc:
                        return data + bytes([b1, b2, b3, b4])
    return None

# 更高效: 使用 CRC 多项式的逆运算（确定性，无需爆破）
# 工具: pip install forcecrc32
```

### 压缩 Oracle (CRIME/BREACH)
服务端先压缩再加密时，通过密文长度变化逐字节猜测 secret（压缩匹配 = 更短密文）。

### HMAC-CRC 线性攻击
CRC 做 HMAC 的底层 hash 时，线性性质导致可以从一个 (msg, mac) 对直接恢复密钥。

### MD5 碰撞（fastcol）
使用 `hashclash/fastcol` 工具生成 MD5 碰撞对。链式拼接 k 次产生 2^k 个同 hash 文件：
```bash
git clone https://github.com/cr-marcstevens/hashclash
./fastcol -o a.bin b.bin < prefix.bin
```

## 相关技术

- [[padding_oracle]] — 另一种不需要密钥的密文篡改技术
- [[aes_ecb]] — 分组密码攻击的通用方法
- [[rsa_basic]] — hash extension 常出现在 RSA 签名验证绕过的组合题中
