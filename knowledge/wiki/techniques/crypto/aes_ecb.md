---
category: crypto
tags: [aes, ecb, cbc, gcm, block_cipher, byte_at_a_time, cut_and_paste, bit_flip, nonce_reuse, chosen_plaintext, 分组密码, 选择明文, 比特翻转, 重放攻击]
triggers: [aes, ecb, cbc, gcm, block cipher, ecb oracle, byte at a time, cut and paste, bit flip, nonce reuse, forbidden attack, identical blocks, 分组密码, aes加密, ecb模式, cbc模式]
related: [rsa_basic, padding_oracle, hash_extension]
---

# AES 分组密码攻击

## 什么时候用

题目使用 AES 分组密码（ECB/CBC/GCM 模式），且存在以下弱点之一：ECB 模式泄露模式、可选择明文加密、CBC 无完整性校验、GCM nonce 重用。

## 前提条件

- **ECB byte-at-a-time**：服务端加密 `user_input || secret`，且使用 ECB 模式
- **ECB cut-and-paste**：服务端用 ECB 加密结构化数据（JSON/cookie），可控制部分字段
- **CBC bit-flip**：服务端用 CBC 加密但无 MAC/HMAC 完整性校验，可修改 IV 或密文
- **GCM nonce reuse**：同一 key 下两次使用相同 nonce 加密

## 攻击步骤

### 1. ECB 模式检测

ECB 模式下相同明文块产生相同密文块，发送重复数据即可检测：

```python
from Crypto.Cipher import AES
import os

def detect_ecb(ciphertext, block_size=16):
    """检测密文是否存在重复块（ECB 特征）"""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))

# 发送至少 3 个块的重复数据触发重复
test_input = b'A' * 48
ct = oracle(test_input)
if detect_ecb(ct):
    print("ECB mode detected!")
```

### 2. ECB Byte-at-a-Time 选择明文攻击

服务端加密 `user_input || secret_suffix`，逐字节恢复 secret：

```python
def ecb_byte_at_a_time(oracle_fn, block_size=16):
    """逐字节恢复 ECB 加密的未知后缀"""
    # 1) 确定块大小和后缀长度
    base_len = len(oracle_fn(b''))
    for i in range(1, 33):
        if len(oracle_fn(b'A' * i)) > base_len:
            block_size = i
            break
    suffix_len = base_len  # 大致等于后缀+padding长度

    known = b''
    for i in range(suffix_len):
        pad_len = block_size - 1 - (len(known) % block_size)
        pad = b'A' * pad_len

        # 获取目标块
        target_ct = oracle_fn(pad)
        block_idx = (pad_len + len(known)) // block_size
        target_block = target_ct[block_idx * 16:(block_idx + 1) * 16]

        # 暴力匹配 256 种可能
        found = False
        for byte_val in range(256):
            test = pad + known + bytes([byte_val])
            test_ct = oracle_fn(test)
            if test_ct[block_idx * 16:(block_idx + 1) * 16] == target_block:
                known += bytes([byte_val])
                found = True
                break
        if not found:
            break  # 遇到 padding 结束

    return known

secret = ecb_byte_at_a_time(oracle)
print(f"Recovered: {secret}")
```

### 3. ECB Cut-and-Paste 块拼接攻击

服务端用 ECB 加密结构化数据（如 `role=user`），通过精心对齐让目标值独占一个块：

```python
def ecb_cut_and_paste(register_fn, login_fn, block_size=16):
    """
    目标：把 role=user 改成 role=admin
    思路：让 "admin" + padding 恰好对齐到一个独立的块
    """
    # Step 1: 构造让 "admin\x0b\x0b...\x0b" 独占一个块的输入
    # 假设格式: email=XXX&role=user
    # 需要 email 长度让 "email=" 到块边界，然后 admin+padding 占下一个块
    prefix_len = block_size - len("email=")  # 使 "email=AAAA..." 对齐
    evil_block = b'admin' + bytes([11] * 11)  # admin + PKCS7(11)
    email1 = b'A' * prefix_len + evil_block + b'@x.co'

    ct1 = register_fn(email1)
    admin_block = ct1[block_size:block_size * 2]  # 提取 admin 块

    # Step 2: 正常注册，让 "role=" 恰好在块末尾
    email2 = b'A' * (block_size - len("email=") - len("&role=") % block_size)
    ct2 = register_fn(email2 + b'@x.co')

    # Step 3: 拼接——用 admin 块替换最后一个块
    forged = ct2[:-(block_size)] + admin_block
    return login_fn(forged)
```

### 4. CBC Bit-Flip 攻击

CBC 解密时 `P[i] = D(C[i]) XOR C[i-1]`，修改 C[i-1] 可精确翻转 P[i] 的任意比特：

```python
def cbc_bitflip(iv, ct, known_plain, target_plain, block_idx=0):
    """
    已知第 block_idx 块的明文 known_plain，
    修改前一块密文（或 IV）使其解密为 target_plain
    """
    ct = bytearray(ct)
    iv = bytearray(iv)

    assert len(known_plain) == len(target_plain) == 16

    if block_idx == 0:
        # 修改 IV
        for i in range(16):
            iv[i] ^= known_plain[i] ^ target_plain[i]
    else:
        # 修改前一个密文块
        offset = (block_idx - 1) * 16
        for i in range(16):
            ct[offset + i] ^= known_plain[i] ^ target_plain[i]

    return bytes(iv), bytes(ct)

# 示例：把 "role=user\x07..." 翻转成 "role=admin\x03..."
# 注意：被修改的那个块会变成乱码，需确保不影响解析
iv, ct = cbc_bitflip(
    original_iv, ciphertext,
    known_plain=b'{"role": "user"}',
    target_plain=b'{"role":"admin"}',
    block_idx=0
)
```

### 5. AES-GCM Nonce Reuse（Forbidden Attack）

同一 key + nonce 加密两条消息，破坏保密性和认证性：

```python
from sage.all import GF, PolynomialRing

def gcm_nonce_reuse(c1, tag1, aad1, c2, tag2, aad2, nonce):
    """
    同 nonce 两条消息 -> 恢复 GHASH 认证密钥 H -> 伪造标签
    """
    # Step 1: CTR keystream 重用 -> 恢复明文
    # 如果已知 p1，则 p2 = c2 XOR c1 XOR p1
    keystream = bytes(a ^ b for a, b in zip(c1, known_p1))
    p2 = bytes(a ^ b for a, b in zip(c2, keystream))

    # Step 2: 恢复 GHASH 密钥 H（在 GF(2^128) 上解多项式）
    # 构造: T1 XOR T2 = P(H) 其中 P 由密文差异决定
    # 分解多项式得到 H 的候选值
    F = GF(2**128, 'x', modulus=x**128 + x**7 + x**2 + x + 1)
    # ... 构造差分多项式并求根 ...

    # Step 3: 用 H 伪造任意消息的标签
    # GHASH(H, aad, ct) = sum(block_i * H^(n-i+1)) + len_block * H
    pass

# 工具: https://github.com/nonce-disrespect/nonce-disrespect
```

## 常见坑

- **块大小判断错误**：AES 块固定 16 字节，但服务端可能有额外前缀。先发送不同长度输入，观察密文长度跳变点来确定前缀长度。
- **ECB byte-at-a-time 前缀干扰**：如果格式是 `prefix || user_input || secret`，需要先确定 prefix 长度，再填充到块边界。发送递增长度输入，找到两个相邻密文块首次相同的点。
- **CBC bit-flip 副作用**：修改 C[i-1] 会使 block i-1 的明文变成乱码。如果服务端校验整个明文的格式（如 JSON），需要确保乱码块不破坏解析。常用技巧：把乱码放在可忽略的字段里。
- **GCM nonce 长度**：标准 GCM nonce 是 12 字节。非标准长度的 nonce 会先经过 GHASH 处理，攻击公式需要相应调整。
- **padding 类型**：ECB/CBC 通常用 PKCS#7 padding（值等于填充字节数），但有些题用 zero-padding 或自定义 padding。
- **pycryptodome vs pycrypto**：用 `from Crypto.Cipher import AES` 时确保装的是 `pycryptodome`（`pip install pycryptodome`），不是已废弃的 `pycrypto`。

## 变体

### ECB 图片加密
BMP/PPM 图片用 ECB 加密后，由于相同像素块产生相同密文块，图片轮廓仍然可见。直接观察密文图片即可识别内容。

### CBC Padding Oracle
CBC 模式下服务端泄露 padding 是否合法，可以逐字节恢复明文。详见 [[padding_oracle]]。

### AES-CTR 重复 nonce
与 GCM 类似，CTR 模式 nonce 重用导致 keystream 重复：`C1 XOR C2 = P1 XOR P2`。配合已知明文或频率分析恢复。

### CBC IV=Key 漏洞
服务端用 key 本身作为 IV 时，提交特殊密文可恢复 key：发送 `C1 || 0_block || C1`，解密报错会泄露 `P1 XOR P3 = IV = Key`。

## 相关技术

- [[padding_oracle]] — CBC padding oracle 逐字节解密
- [[rsa_basic]] — RSA 攻击，CTF 常与 AES 混合出题
- [[hash_extension]] — 哈希扩展攻击，绕过 MAC 校验
