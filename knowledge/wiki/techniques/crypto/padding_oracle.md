---
category: crypto
tags: [padding_oracle, pkcs7, cbc, aes, bleichenbacher, pkcs1, oracle, byte_by_byte, padbuster, 填充攻击, 填充预言, 逐字节解密, 密文伪造]
triggers: [padding oracle, pkcs7, pkcs#7, valid padding, invalid padding, cbc oracle, padding error, padbuster, bleichenbacher, pkcs1 v1.5, rsa padding, 填充预言, 填充攻击, padding 错误, 解密失败]
related: [aes_ecb, rsa_basic, hash_extension]
---

# Padding Oracle 攻击

## 什么时候用

服务端使用 CBC 模式加密，且能区分 "padding 合法" 和 "padding 不合法"（通过不同的错误信息、HTTP 状态码、响应时间，甚至是否继续处理请求）。只需要这 1 bit 信息就能逐字节恢复全部明文，甚至伪造密文。

## 前提条件

- **CBC 模式加密**：ECB 没有链式结构，不适用
- **可区分 padding 错误**：HTTP 500 vs 200、`Invalid padding` vs `Decryption failed`、响应时间差异都算
- **可重复提交密文**：每次提交都用相同密钥解密
- **知道块大小**：AES 固定 16 字节
- ⚠️ 服务端限制请求次数时需要优化查询策略（每块最多 256×16 = 4096 次）
- ⚠️ 使用 AEAD（GCM/CCM/ChaCha20-Poly1305）的系统不受影响

## 攻击步骤

### 1. PKCS#7 Padding 规则

PKCS#7 填充：填充 N 个字节，每个字节的值都是 N：

```
数据长度 mod 16 = 15 -> 填充 01
数据长度 mod 16 = 14 -> 填充 02 02
数据长度 mod 16 = 13 -> 填充 03 03 03
...
数据长度 mod 16 = 0  -> 填充 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
```

服务端解密后会验证最后 N 个字节是否都等于 N，不合法就报错——这就是 oracle。

### 2. 攻击原理

CBC 解密：`P[i] = AES_DEC(C[i]) XOR C[i-1]`

设中间值 `I[i] = AES_DEC(C[i])`（我们不知道），那么 `P[i] = I[i] XOR C[i-1]`。

攻击目标：通过构造 `C'[i-1]` 使得 `I[i] XOR C'[i-1]` 的最后一字节为 `\x01`（合法 padding）。
当 oracle 返回 "合法" 时：`I[i][15] = C'[i-1][15] XOR 0x01`，从而 `P[i][15] = I[i][15] XOR C[i-1][15]`。

### 3. 完整 Python 实现

```python
import requests
from Crypto.Util.Padding import unpad

BLOCK_SIZE = 16

def oracle(iv, ct):
    """向服务端提交密文，返回 padding 是否合法"""
    resp = requests.post('http://target/decrypt', data={
        'iv': iv.hex(),
        'ct': ct.hex()
    })
    # 根据题目调整判断条件
    return 'padding' not in resp.text.lower() and resp.status_code != 500

def decrypt_block(prev_block, target_block):
    """用 padding oracle 解密单个 16 字节块"""
    intermediate = bytearray(16)  # AES_DEC(target_block)
    plaintext = bytearray(16)

    for byte_pos in range(15, -1, -1):
        pad_val = 16 - byte_pos  # 当前要构造的 padding 值

        # 构造已知部分的 padding
        crafted = bytearray(16)
        for k in range(byte_pos + 1, 16):
            crafted[k] = intermediate[k] ^ pad_val

        # 爆破当前字节
        for guess in range(256):
            crafted[byte_pos] = guess
            if oracle(bytes(crafted), target_block):
                # 特殊情况：byte_pos=15 时可能匹配 \x02\x02 而非 \x01
                if byte_pos == 15:
                    # 验证：修改倒数第二个字节，如果仍然合法说明确实是 \x01
                    check = bytearray(crafted)
                    check[14] ^= 0x01
                    if not oracle(bytes(check), target_block):
                        continue  # 不是 \x01，跳过

                intermediate[byte_pos] = guess ^ pad_val
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                break

    return bytes(plaintext)

def padding_oracle_attack(iv, ciphertext):
    """解密完整密文"""
    blocks = [iv]
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        blocks.append(ciphertext[i:i + BLOCK_SIZE])

    plaintext = b''
    for i in range(1, len(blocks)):
        pt_block = decrypt_block(blocks[i - 1], blocks[i])
        plaintext += pt_block
        print(f"Block {i}: {pt_block}")

    # 去除 PKCS#7 padding
    try:
        plaintext = unpad(plaintext, BLOCK_SIZE)
    except ValueError:
        pass  # padding 不标准时保留原样
    return plaintext

# 使用
iv = bytes.fromhex('...')
ct = bytes.fromhex('...')
result = padding_oracle_attack(iv, ct)
print(f"Decrypted: {result}")
```

### 4. 使用 PadBuster 工具

```bash
# 安装: apt install padbuster 或 gem install padbuster
padbuster http://target/decrypt ENCRYPTED_HEX 16 \
  -encoding 0 \
  -error "Invalid padding" \
  -cookies "session=abc123"

# -encoding: 0=hex, 1=base64, 2=raw
# -error: 标识 padding 错误的响应特征
# -plaintext "admin=true"  # 加密模式：构造指定明文的密文
```

### 5. 密文伪造（Encrypt 模式）

知道 intermediate 值后，可以构造解密为任意明文的密文：

```python
def forge_ciphertext(target_plaintext):
    """构造解密为 target_plaintext 的密文（无需密钥）"""
    from Crypto.Util.Padding import pad
    pt = pad(target_plaintext, BLOCK_SIZE)
    blocks = [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]

    # 从最后一个块开始，随机选择最后一个密文块
    import os
    ct_blocks = [os.urandom(BLOCK_SIZE)]

    for i in range(len(blocks) - 1, -1, -1):
        # 用 oracle 恢复 intermediate
        intermediate = recover_intermediate(ct_blocks[0])
        # 构造前一个密文块: C[i-1] = I[i] XOR P[i]
        prev = bytes(a ^ b for a, b in zip(intermediate, blocks[i]))
        ct_blocks.insert(0, prev)

    iv = ct_blocks[0]
    ct = b''.join(ct_blocks[1:])
    return iv, ct
```

## 常见坑

- **byte_pos=15 的误判**：爆破最后一个字节时，`\x02\x02` 也是合法 padding。必须验证：翻转倒数第二个字节后是否仍然合法。如果仍然合法，说明不是 `\x01`。
- **网络延迟导致误判**：timing-based oracle 对网络抖动敏感。解决：多次请求取中位数，或加大超时差异的阈值。
- **请求限制/封禁**：每块最多 4096 次请求，10 块就是 4 万次。加 sleep 降速，或用 session 池轮换。
- **服务端无差异返回**：有些实现在 padding 错误和解密错误时返回相同结果。尝试看响应时间差异（timing oracle）——padding 错误通常更快返回。
- **IV 不可控**：如果 IV 固定且不可修改，第一个明文块无法用标准方式恢复（但后续块仍然可以）。
- **base64 vs hex**：注意服务端期望的编码格式。base64 的 padding 字符 `=` 可能需要 URL encode。
- **PKCS#5 vs PKCS#7**：PKCS#5 是 PKCS#7 在 8 字节块上的特例，AES（16 字节块）用的是 PKCS#7。实际处理方式完全相同。

## 变体

### Timing-Based Oracle
服务端不返回不同错误信息，但 padding 合法时处理时间更长（继续解析数据），不合法时快速返回。通过统计响应时间区分：

```python
import time

def timing_oracle(iv, ct, threshold=0.1):
    start = time.time()
    resp = requests.post(URL, data={'iv': iv.hex(), 'ct': ct.hex()})
    elapsed = time.time() - start
    return elapsed > threshold  # 慢 = padding 合法
```

### Bleichenbacher RSA PKCS#1 v1.5 Padding Oracle
RSA 加密的 PKCS#1 v1.5 填充格式：`00 02 [random_nonzero_bytes] 00 [message]`。
服务端区分 padding 是否以 `00 02` 开头，自适应选择密文攻击约 10000 次查询恢复明文：

```python
def bleichenbacher(c0, n, e, oracle_fn, k):
    """RSA PKCS#1 v1.5 padding oracle attack"""
    B = pow(2, 8 * (k - 2))
    # 搜索 s 使得 c0 * s^e mod n 有合法 padding
    s = (n + 3 * B - 1) // (3 * B)
    while True:
        c_test = (c0 * pow(s, e, n)) % n
        if oracle_fn(c_test):
            break
        s += 1
    # 迭代缩小 [a, b] 区间直到收敛
    # 完整实现较长，推荐使用 TLS-Attacker 或 ROBOT 工具
```

### Manger's Attack（RSA-OAEP）
RSA-OAEP 的 padding oracle 变体。Oracle 区分 "首字节是否为 0x00"。三步攻击：乘法搜索 -> 粗定位 -> 二分收敛，约 1024 次查询解密 RSA-1024。常见于 Python 短路求值导致的 timing oracle。

### CBC-R（CBC Reverse）
结合 padding oracle 的 decrypt 能力和 CBC 结构，可以构造加密任意明文的合法密文——即使不知道密钥。这在 cookie/token 伪造中非常实用。

## 相关技术

- [[aes_ecb]] — AES 其他模式攻击（ECB/GCM）
- [[rsa_basic]] — RSA 基础攻击，Bleichenbacher 属于 RSA+Padding 交叉领域
- [[hash_extension]] — 另一种绕过服务端校验的攻击
