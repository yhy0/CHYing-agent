---
name: cryptography
description: Use when facing cryptography challenges involving cipher analysis, key recovery, mathematical attacks, or protocol weaknesses
---

# CTF Crypto Solver Skill

## Core Objective

你是一个专业的 CTF Crypto 解题助手。你的目标是：

1. **识别加密类型** — 从参数、代码、输出特征判断
2. **查阅攻击模块** — Read 对应 module 获取完整攻击代码
3. **选择最优攻击** — 按 dispatch table 优先级执行
4. **生成可运行脚本** — 直接产出 exploit，不做空泛分析

**关键原则：modules/ 下有 14 个文件包含完整攻击代码和真实 CTF writeup。本文件是调度入口，详细实现务必 Read 对应 module。**

---

## 标准解题流程

```
1. 读题 → 提取参数 (n/e/c, key/iv/mode, ciphertext, source code)
2. 查 dispatch table → 匹配加密类型 + 识别漏洞模式
3. 快速尝试 "first try" 命令 (RsaCtfTool / factordb / 直接数学)
4. 若 first try 失败 → Read 对应 module 获取高级攻击
5. 编写并运行完整 exploit 脚本
6. 提取 flag → 验证格式
```

---

## Dispatch Table — 密码类型识别与攻击路由

### 1. RSA

**识别特征**: 出现 `n, e, c` 参数；`.pem` 公钥文件；`pow(m, e, n)` 代码；大整数（通常 >256 位）

| 漏洞模式 | 识别方法 | 攻击 | 说明 |
|---------|---------|------|------|
| 小 n | n < 512 bit | factordb / yafu | 直接分解 |
| 小 e (e=3) | e ≤ 5 且 c 较小 | 整数开根 `gmpy2.iroot(c,e)` | m^e 未超过 n 则直接开根 |
| 共模攻击 | 同 n 不同 e 加密同一 m | 扩展 GCD | gcd(e1,e2)=1 时恢复 m |
| Wiener | e 很大 (接近 n) | 连分数展开 | d < n^0.25 / 3 |
| Fermat | p, q 相近 | Fermat 分解 | \|p-q\| < n^(1/4) |
| Pollard p-1 | p-1 只含小因子 | Pollard p-1 | B-smooth 的 p-1 |
| Hastad 广播 | 同 m 用不同 n 加密, 小 e | CRT + 开根 | 需 e 组密文 |
| Coppersmith | 已知明文高位/部分 p | SageMath `small_roots()` | 最强通用攻击 |
| Batch GCD | 多个 n 共享素因子 | `gcd(n1, n2)` | 多密钥场景 |
| dp/dq 泄露 | 已知 dp, dq, qinv | CRT 直接解密 | 部分私钥恢复 |
| CRT 故障 | 一次正确一次错误签名 | `gcd(s_bad^e - m, n)` | 故障注入场景 |
| e 与 phi 不互素 | `gcd(e, phi) > 1` | CRT + nthroot_mod per prime | 需分解 n |
| p = q | n 是完全平方 | `gmpy2.isqrt(n)` 检测 | phi = p*(p-1) |

**First try**:
```bash
# 自动化尝试所有已知攻击
rsactftool --publickey pub.pem --private --attack all
# 或指定参数
rsactftool -n $N -e $E --uncipher $C --attack all
```

```python
# factordb 查询
from factordb.factordb import FactorDB
f = FactorDB(n)
f.connect()
factors = f.get_factor_list()
if len(factors) >= 2:
    p, q = factors[0], factors[1]
```

**详细攻击代码** → `Read modules/rsa-attacks.md` (基础攻击: small e, common modulus, Wiener, Pollard, Hastad, Coppersmith, Manger oracle)
**高级技术** → `Read modules/rsa-attacks-2.md` (batch GCD, dp/dq 恢复, CRT fault, 同态 oracle, p=q bypass)
**RSA 基础流程** → `Read modules/rsa.md`

---

### 2. AES / 分组密码 (Block Ciphers)

**识别特征**: `AES`, `DES` 关键字；`MODE_CBC/ECB/GCM/CFB`；16/32 字节密钥；PKCS7 padding；base64 密文

| 漏洞模式 | 识别方法 | 攻击 | 说明 |
|---------|---------|------|------|
| ECB 模式泄漏 | 相同明文块→相同密文块 | byte-at-a-time oracle | 逐字节恢复 |
| ECB cut-and-paste | 可控制明文在块边界 | 拼接已知密文块 | 角色/权限伪造 |
| CBC bit-flip | 需要修改解密后明文 | 翻转前一块密文位 | C'[i] ^= old ^ new |
| CBC IV bit-flip | IV 可控 | 同上但针对第一块 | 认证绕过场景 |
| Padding Oracle | 服务器区分 padding valid/invalid | 逐字节解密 (见下方模板) | 最高频 AES 考点 |
| GCM nonce 重用 | 同 nonce 加密两次 | 恢复 GHASH key H | forbidden attack |
| CFB-8 静态 IV | AES-CFB 8-bit feedback | 状态重建 | 16 字节后完全确定 |
| 弱密钥/可预测 IV | key 来自 hash 或时间 | 暴力 / 推导 | 检查密钥生成 |
| DES 弱密钥 | OFB 模式 + 弱密钥 | 密钥空间仅 4 个 | 检查 `DES.key_size` |

**First try**:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), 16)
```

**详细攻击代码** → `Read modules/modern-ciphers.md` (padding oracle, GCM nonce reuse, CBC-MAC, CFB-8)
**更多技术** → `Read modules/modern-ciphers-2.md` (ECB byte-at-a-time, CBC IV bit-flip, DES weak keys, hash 扩展)

---

### 3. 流密码 (Stream Ciphers)

**识别特征**: `LFSR`, `shift register`, 位操作 (`^`, `>>`, `<<`, `& tap_mask`)；RC4；自定义 XOR keystream 生成器

| 漏洞模式 | 识别方法 | 攻击 | 说明 |
|---------|---------|------|------|
| LFSR 已知明文 | 有 known plaintext → 得 keystream | Berlekamp-Massey 恢复多项式 | 需 2L bits (L=LFSR 长度) |
| LFSR 相关攻击 | 多 LFSR 组合但有 bias | 暴力单个 LFSR + 相关性检测 | combining generator |
| Galois LFSR | 反馈在输出端 | 自相关分析恢复 taps | 和 Fibonacci LFSR 不同 |
| RC4 偏差 | RC4 + 多次加密 | 第二字节偏差统计 | 需要多组密文 |
| XOR 重复密钥 | 密钥比明文短, 循环 XOR | 频率分析 / crib dragging | 先确定密钥长度 |

**First try**:
```python
# SageMath: Berlekamp-Massey 恢复 LFSR
from sage.all import GF, berlekamp_massey
F = GF(2)
keystream_bits = [F(b) for b in known_keystream]
poly = berlekamp_massey(keystream_bits)
print(f"Feedback polynomial: {poly}, degree (LFSR length): {poly.degree()}")
```

**详细攻击代码** → `Read modules/stream-ciphers.md` (Berlekamp-Massey 完整实现, 相关攻击, Galois LFSR, RC4)

---

### 4. Hash 攻击

**识别特征**: `MD5`, `SHA1`, `SHA256`；`HMAC`；`hash(secret + data)` 结构；碰撞要求；签名验证

| 漏洞模式 | 识别方法 | 攻击 | 说明 |
|---------|---------|------|------|
| 长度扩展 | `hash(secret \|\| msg)` 做 MAC | hash length extension | MD5/SHA1/SHA256 均可 |
| MD5 碰撞 | 需要两个不同 msg 同 hash | fastcol / hashclash | 选择前缀碰撞 |
| 弱 HMAC (CRC) | HMAC 用 CRC32 做 hash | 线性性质伪造 | CRC 不是密码学 hash |
| 时间侧信道 | 逐字节比较 hash | timing attack 逐字节猜 | 字节正确时响应慢 |
| Meet-in-middle | hash 链或双重加密 | MITM 降低复杂度 | 2^n → 2^(n/2) |
| Sponge 碰撞 | 自定义 sponge hash | MITM on partial state | 利用小容量 |
| 暴力/字典 | 短密码 / 弱密钥 | hashcat / john | 已知 hash 类型 |

**First try**:
```bash
# Hash 类型识别
hashid 'e10adc3949ba59abbe56e057f20f883e'

# 暴力破解
hashcat -m 0 hash.txt wordlist.txt    # MD5
john --format=raw-sha256 hash.txt      # SHA256
```

```python
# Hash 长度扩展 (使用 hashpumpy: pip install hashpumpy)
import hashpumpy
new_hash, new_msg = hashpumpy.hashpump(
    original_hash,    # 已知的 hash(secret || original_data)
    original_data,    # 已知的 original_data
    append_data,      # 要追加的数据
    secret_length     # secret 长度 (可爆破 1-64)
)
```

**详细攻击代码** → `Read modules/modern-ciphers-2.md` (hash length extension, MD5 fastcol, sponge MITM, custom hash reversal)

---

### 5. 椭圆曲线 (ECC)

**识别特征**: `EllipticCurve`, 曲线参数 `(a, b, p)`, 点坐标 `(Gx, Gy)`, `ECDSA`, `scalar multiplication`

| 漏洞模式 | 识别方法 | 攻击 | 说明 |
|---------|---------|------|------|
| Smart's attack | `E.order() == p` (anomalous) | p-adic lifting | O(1) 解 ECDLP |
| 小子群 | `E.order()` 有小因子 | Pohlig-Hellman + CRT | smooth order |
| 无效曲线 | 不验证点在曲线上 | 发送弱曲线上的点 | 泄露密钥 bits |
| 奇异曲线 | `4a³+27b² ≡ 0 (mod p)` | 映射到加法/乘法群 | DLP 变 trivial |
| ECDSA nonce 重用 | 两个签名用同一 k | 代数恢复私钥 (见下方模板) | 最高频 ECC 考点 |
| ECDSA nonce bias | k 有已知 MSB/LSB | HNP → LLL 格攻击 | 部分 nonce 泄露 |
| Ed25519 torsion | 不检查 torsion 分量 | 构造 8-torsion 点 | 签名侧信道 |

**First try**:
```python
# SageMath: 检测 anomalous + 求离散对数
from sage.all import *
E = EllipticCurve(GF(p), [a, b])
print(f"Order = {E.order()}, p = {p}, anomalous = {E.order() == p}")
G = E(Gx, Gy); Q = E(Qx, Qy)
secret = G.discrete_log(Q)  # Sage 自动选择最优算法
```

**详细攻击代码** → `Read modules/ecc-attacks.md` (Smart's attack 手动实现, ECDSA nonce reuse, 无效曲线, DSA brute force)

---

### 6. PRNG 预测

**识别特征**: `random.randint()`, `random.getrandbits()`, `Math.random()` (JS), `srand(time())`, `MT19937`, `LCG`

| 漏洞模式 | 识别方法 | 攻击 | 说明 |
|---------|---------|------|------|
| MT19937 状态恢复 | Python random, 624+ 输出 | untemper 恢复内部状态 (见下方模板) | 最高频 PRNG 考点 |
| MT19937 (z3) | 输出被截断/变换 | z3 symbolic solving | getrandbits(63) 等 |
| 时间种子 | `srand(time())` 或 `random.seed(int(time()))` | 爆破时间窗口 | 通常 ±1000 秒 |
| LCG 恢复 | `x_{n+1} = a*x_n + b mod m` | 连续输出恢复 a, b, m | 3+ 输出即可 |
| V8 XorShift128+ | `Math.random()` in Node/Chrome | 从 float 恢复状态 | z3 求解 |
| C rand() | `srand`/`rand` libc | ctypes 同步 | 需知种子 |

**First try**:
```python
# MT19937 快速检测: 如果能拿到 624 个 32-bit 输出
import random
outputs = [...]  # 624 个连续输出
# 见下方 "MT19937 状态恢复" 完整模板
```

**详细攻击代码** → `Read modules/prng.md` (MT19937 完整恢复, z3 symbolic, V8 XorShift128+, LCG, 时间种子, logistic map)

---

### 7. 格密码 / 高级数学 (Lattice / Advanced Math)

**识别特征**: `LLL`, `lattice`, `knapsack`, `CVP/SVP`, `LWE`, 超大维度矩阵, Coppersmith 提示

| 漏洞模式 | 识别方法 | 攻击 | 说明 |
|---------|---------|------|------|
| Knapsack (背包) | 子集和问题 / Merkle-Hellman | LLL 格基约简 (见下方模板) | 经典格攻击 |
| Coppersmith 小根 | RSA partial info / 多项式方程 | SageMath `small_roots()` (见下方模板) | 配合 RSA |
| LWE | `b = As + e (mod q)` | CVP / BDD on lattice | 噪声线性方程 |
| HNP (隐藏数问题) | ECDSA 部分 nonce | LLL 恢复隐藏值 | nonce bias 场景 |
| Approximate GCD | 带噪声的 GCD | LLL | DGHV 方案 |

**First try**:
```python
# SageMath LLL
from sage.all import *
M = Matrix(ZZ, [...])  # 构造格基矩阵
L = M.LLL()
# 检查短向量是否包含解
```

**详细攻击代码** → `Read modules/advanced-math.md` (LLL, Coppersmith, LWE/CVP, knapsack, 四元数 RSA, isogeny)

---

### 8. ZKP / 高级协议

**识别特征**: `Groth16`, `SNARK`, `proof`, `verifier`, 配对 (pairing), `circom`, `KZG commitment`

| 漏洞模式 | 识别方法 | 攻击 | 说明 |
|---------|---------|------|------|
| Groth16 delta=gamma | trusted setup 参数错误 | 伪造 proof 的 C 分量 | 绕过验证 |
| 未约束变量 | proof replay / 可锻造 | 复用已知 proof | nullifier 等 |
| ZKP 信息泄露 | commit-reveal 方案 | PRNG 预测 salt / brute force 值域 | 颜色等小域 |
| Z3 约束求解 | 自定义验证逻辑 | 建模为 SMT 公式 | 通用万能工具 |
| Shamir SSS 弱系数 | 系数可预测/不够随机 | 恢复 secret 不需要阈值份额 | 检查 randomness |
| KZG pairing oracle | 可查询 pairing | 利用 oracle 恢复多项式信息 | 代数攻击 |

**First try**:
```python
# Z3 通用约束求解模板
from z3 import *
s = Solver()
x = BitVec('x', 64)
s.add(...)  # 从题目代码翻译约束
if s.check() == sat:
    print(s.model())
```

**详细攻击代码** → `Read modules/zkp-and-advanced.md` (Groth16, Z3 完整指南, Shamir SSS, KZG, garbled circuits, DV-SNARG)

---

### 9. 古典密码 (Classic Ciphers)

**识别特征**: 纯字母密文；出现 `shift`, `vigenere`, `substitution`；base64/hex 编码后的简单密文；图形密码

| 漏洞模式 | 识别方法 | 攻击 | 说明 |
|---------|---------|------|------|
| Caesar / ROT | 纯字母 + 短密文 | 暴力 26 种 shift | `chr((ord(c)-65-k)%26+65)` |
| Vigenere | 长字母密文 + 重复模式 | Kasiski 测试 → 频率分析 | 先定 key 长度 |
| Vigenere 已知明文 | 知 flag 格式 | 直接推 key | `key[i] = (c[i]-p[i]) % 26` |
| 替换密码 | 字母频率不均匀 | quipqiup.com / 频率分析 | 单表替换 |
| XOR 重复密钥 | 二进制数据 + 短密钥 | 频率分析 / crib dragging | 密钥长度 ≤ 32 |
| XOR 已知文件头 | 加密已知格式文件 | 文件头 XOR → key | PNG/PDF/PK header |
| Many-time pad | OTP 密钥重用 | crib dragging / XOR 互消 | c1⊕c2 = m1⊕m2 |
| 栅栏密码 | 字母排列有规律 | 尝试 2-10 rails | rail fence |

**First try**:
```bash
# 在线工具
# quipqiup.com — 替换密码自动求解
# dcode.fr — 各类古典密码
# CyberChef — 编码转换 + 多步解密
```

```python
# XOR 密钥恢复 (已知文件头)
known_header = b'\x89PNG\r\n\x1a\n'  # PNG header
key = bytes(c ^ p for c, p in zip(ciphertext[:len(known_header)], known_header))
plaintext = bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))
```

**详细攻击代码** → `Read modules/classic-ciphers.md` (Vigenere Kasiski, XOR variants, OTP key reuse, homophonic, grid permutation)

---

### 10. 奇异密码体制 (Exotic / Uncommon)

**识别特征**: 非标准代数结构；braid group; tropical semiring; Paillier; ElGamal; FPE; 同态加密

**First try**: 仔细阅读题目代码，理解代数结构，然后 Read 对应 module。

**详细攻击代码** → `Read modules/exotic-crypto.md` (braid group DH, tropical semiring, Paillier, ElGamal, FPE Feistel)
**历史密码** → `Read modules/historical.md` (Lorenz SZ40/42)

---

## 关键攻击模板 (Top 8 — 完整可运行)

### Template A: Padding Oracle Attack (CBC)

最高频 AES 考点。服务器返回 padding valid/invalid 信息即可逐字节解密。

```python
#!/usr/bin/env python3
"""Padding Oracle Attack — 逐字节解密 CBC 密文"""
import requests  # 或 pwntools 的 remote()

BLOCK_SIZE = 16

def oracle(payload: bytes) -> bool:
    """发送 payload，返回 padding 是否有效。根据题目修改此函数。"""
    # 方式 1: HTTP
    # r = requests.post(URL, data={'ct': payload.hex()})
    # return 'error' not in r.text  # padding valid 时无 error
    #
    # 方式 2: socket
    # from pwn import remote
    # io = remote(HOST, PORT)
    # io.send(payload)
    # resp = io.recvline()
    # io.close()
    # return b'OK' in resp
    pass

def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """解密单个块，返回明文 bytes"""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_value = BLOCK_SIZE - byte_pos
        # 构造已知部分的 padding
        crafted = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            crafted[k] = intermediate[k] ^ pad_value

        found = False
        for guess in range(256):
            crafted[byte_pos] = guess
            test_payload = bytes(crafted) + target_block
            if oracle(test_payload):
                # 排除误报: 当 byte_pos 非最后一位时翻转前一位确认
                if byte_pos < BLOCK_SIZE - 1 or True:
                    intermediate[byte_pos] = guess ^ pad_value
                    plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                    found = True
                    break
        if not found:
            raise Exception(f"Failed at position {byte_pos}")

    return bytes(plaintext)

def padding_oracle_decrypt(ciphertext: bytes, iv: bytes) -> bytes:
    """完整解密 (不含 IV 块)"""
    blocks = [iv] + [ciphertext[i:i+BLOCK_SIZE]
                     for i in range(0, len(ciphertext), BLOCK_SIZE)]
    plaintext = b''
    for i in range(1, len(blocks)):
        pt_block = decrypt_block(blocks[i-1], blocks[i])
        plaintext += pt_block
        print(f"Block {i}: {pt_block}")
    # 去除 PKCS7 padding
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]

# 使用示例
# iv = bytes.fromhex('...')
# ct = bytes.fromhex('...')
# print(padding_oracle_decrypt(ct, iv))
```

---

### Template B: RSA Coppersmith Small Roots (SageMath)

已知明文高位/部分 p 时恢复完整值。**必须使用 SageMath**。

```python
#!/usr/bin/env sage
"""RSA Coppersmith — 三种常见场景"""
from sage.all import *

# ─── 场景 1: 已知 p 的高位 (Known High Bits of p) ───
def factor_with_high_bits_of_p(n, p_high, unknown_bits):
    """已知 p 的高位, 恢复完整的 p
    p_high: p 的已知高位值 (低位为0)
    unknown_bits: 未知的低位比特数
    """
    F = PolynomialRing(Zmod(n), 'x')
    x = F.gen()
    f = p_high + x
    # beta=0.5: 我们找的根 < n^beta 的因子
    # epsilon 越小越精确但越慢
    roots = f.small_roots(X=2^unknown_bits, beta=0.5, epsilon=0.02)
    if roots:
        p = int(p_high + roots[0])
        assert n % p == 0
        return p, n // p
    return None

# ─── 场景 2: 已知明文高位 (Stereotyped Message) ───
def recover_message_high_bits(n, e, c, m_high, unknown_bits):
    """已知 m 的高位, 恢复完整 m
    m_high: 已知的高位部分
    unknown_bits: 未知低位的比特数
    """
    F = PolynomialRing(Zmod(n), 'x')
    x = F.gen()
    f = (m_high + x)^e - c
    roots = f.small_roots(X=2^unknown_bits, beta=1.0)
    if roots:
        return int(m_high + roots[0])
    return None

# ─── 场景 3: Franklin-Reiter Related Message Attack ───
def franklin_reiter(n, e, c1, c2, a, b):
    """两条相关明文: m2 = a*m1 + b, 已知 a, b
    只对 e=3 高效 (gcd of polynomials)
    """
    R = PolynomialRing(Zmod(n), 'x')
    x = R.gen()
    f1 = x^e - c1
    f2 = (a*x + b)^e - c2
    g = f1.gcd(f2)
    m1 = -g.monic().coefficients()[0]
    return int(m1) % n

# 使用示例
# p, q = factor_with_high_bits_of_p(n, p_high, 128)
# m = recover_message_high_bits(n, e, c, m_high, 64)
```

---

### Template C: MT19937 State Recovery (Python random)

观察 624 个连续 32-bit 输出即可完全预测后续所有值。

```python
#!/usr/bin/env python3
"""MT19937 状态恢复 — 从 624 个输出恢复并预测"""
import random

def untemper(y):
    """逆向 MT19937 的 tempering 变换"""
    # 逆 y ^= y >> 18
    y ^= y >> 18
    # 逆 y ^= (y << 15) & 0xefc60000
    y ^= (y << 15) & 0xefc60000
    # 逆 y ^= (y << 7) & 0x9d2c5680 (需多轮)
    for _ in range(7):
        y ^= (y << 7) & 0x9d2c5680
    # 逆 y ^= y >> 11 (需两轮)
    y ^= y >> 11
    y ^= y >> 22
    return y

def clone_mt(outputs_32bit):
    """从 624 个连续 32-bit 输出克隆 MT 状态
    之后调用 cloned.random() / .getrandbits() 即可预测
    """
    assert len(outputs_32bit) >= 624
    state = [untemper(o) for o in outputs_32bit[:624]]
    cloned = random.Random()
    # state format: (3, tuple(624 ints + index), None)
    cloned.setstate((3, tuple(state + [624]), None))
    return cloned

# ─── 当输出不是 32-bit 时 (如 getrandbits(63), randrange) ───
def mt_z3_recovery(outputs_63bit):
    """用 z3 处理非 32-bit 对齐的输出"""
    from z3 import BitVec, LShR, Solver, sat

    def symbolic_temper(y):
        y = y ^ (LShR(y, 11))
        y = y ^ ((y << 7) & 0x9d2c5680)
        y = y ^ ((y << 15) & 0xefc60000)
        y = y ^ (LShR(y, 18))
        return y

    mt = [BitVec(f'mt_{i}', 32) for i in range(624)]
    s = Solver()

    for i, out63 in enumerate(outputs_63bit):
        if 2*i + 1 >= 624:
            break
        y1 = symbolic_temper(mt[2*i])
        y2 = symbolic_temper(mt[2*i + 1])
        # getrandbits(63) = (y1 << 31) | (y2 >> 1)
        s.add((y1 << 31) | (LShR(y2, 1)) == out63)

    if s.check() == sat:
        model = s.model()
        state = [model[mt[i]].as_long() for i in range(624)]
        return state
    return None

# 使用示例
# outputs = [server.get_random() for _ in range(624)]
# cloned = clone_mt(outputs)
# next_value = cloned.getrandbits(32)  # 预测!
```

---

### Template D: AES-ECB Byte-at-a-Time Oracle

经典 chosen-plaintext 攻击。Oracle 加密 `user_input || secret`，逐字节恢复 secret。

```python
#!/usr/bin/env python3
"""AES-ECB byte-at-a-time — 逐字节恢复 unknown secret"""

BLOCK_SIZE = 16

def ecb_oracle(plaintext: bytes) -> bytes:
    """发送 plaintext，返回 ECB(plaintext || secret)
    根据题目实现: HTTP / socket / 本地调用
    """
    pass

def detect_block_size():
    """检测块大小"""
    prev_len = len(ecb_oracle(b''))
    for i in range(1, 64):
        curr_len = len(ecb_oracle(b'A' * i))
        if curr_len > prev_len:
            return curr_len - prev_len
    return 16

def recover_secret():
    """逐字节恢复 secret"""
    secret_len = len(ecb_oracle(b''))
    recovered = b''

    for i in range(secret_len):
        block_idx = i // BLOCK_SIZE
        byte_idx = i % BLOCK_SIZE
        # 填充使目标字节在块末尾
        padding = b'A' * (BLOCK_SIZE - 1 - byte_idx)
        target = ecb_oracle(padding)
        target_block = target[block_idx * BLOCK_SIZE : (block_idx + 1) * BLOCK_SIZE]

        # 逐字节暴力
        for b in range(256):
            test_input = padding + recovered + bytes([b])
            test_output = ecb_oracle(test_input)
            test_block = test_output[block_idx * BLOCK_SIZE : (block_idx + 1) * BLOCK_SIZE]
            if test_block == target_block:
                recovered += bytes([b])
                print(f"[{i}] Found: {chr(b) if 32<=b<127 else '?'} -> {recovered}")
                break
        else:
            print(f"[{i}] Failed, stopping. Recovered so far: {recovered}")
            break

    return recovered

# flag = recover_secret()
```

---

### Template E: LFSR Berlekamp-Massey Attack

已知部分 keystream 即可恢复 LFSR 多项式和初始状态，预测全部输出。

```python
#!/usr/bin/env python3
"""LFSR 攻击 — Berlekamp-Massey + 预测"""

def berlekamp_massey_gf2(bits):
    """GF(2) 上的 Berlekamp-Massey 算法
    输入: keystream bits 列表 [0,1,1,0,...]
    输出: (feedback_poly_coeffs, LFSR_length)
    """
    n = len(bits)
    C = [1]  # 当前多项式
    B = [1]  # 上一次更新的多项式
    L = 0    # LFSR 长度
    m = 1    # 自上次更新的步数
    b = 1    # 上次 discrepancy

    for i in range(n):
        # 计算 discrepancy
        d = bits[i]
        for j in range(1, L + 1):
            if j < len(C):
                d ^= C[j] & bits[i - j]

        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            shift = [0] * m + B
            while len(C) < len(shift):
                C.append(0)
            for j in range(len(shift)):
                C[j] ^= shift[j]
            L = i + 1 - L
            B = T
            b = d
            m = 1
        else:
            shift = [0] * m + B
            while len(C) < len(shift):
                C.append(0)
            for j in range(len(shift)):
                C[j] ^= shift[j]
            m += 1

    return C[1:L+1], L

def predict_lfsr(state, taps, n_bits):
    """用恢复的状态和 taps 预测后续 bits"""
    output = list(state)
    for _ in range(n_bits):
        new_bit = 0
        for t in taps:
            new_bit ^= output[-(t+1)]
        output.append(new_bit & 1)
    return output[len(state):]

# 使用示例
# keystream = [plaintext[i] ^ ciphertext[i] for i in range(len(plaintext))]
# bits = []
# for byte in keystream:
#     bits.extend([(byte >> (7-j)) & 1 for j in range(8)])
# taps, length = berlekamp_massey_gf2(bits)
# future = predict_lfsr(bits[:length], taps, 1000)
```

---

### Template F: Hash Length Extension Attack

当 MAC = `hash(secret || message)` 时，无需知道 secret 即可构造 `hash(secret || message || padding || append)`。

```python
#!/usr/bin/env python3
"""Hash Length Extension — 使用 hashpumpy + 爆破 secret 长度"""
import hashpumpy

def hash_length_extension(original_hash, original_data, append_data, verify_fn):
    """verify_fn(new_hash_hex, forged_msg_bytes) -> bool
    爆破 secret 长度 1-64, 找到有效的扩展
    """
    for secret_len in range(1, 65):
        new_hash, new_msg = hashpumpy.hashpump(
            original_hash,    # hex string: 已知的 hash(secret || original_data)
            original_data,    # bytes: 已知的 original_data
            append_data,      # bytes: 要追加的数据
            secret_len        # int: 猜测的 secret 长度
        )
        if verify_fn(new_hash, new_msg):
            print(f"[+] Secret length: {secret_len}")
            print(f"[+] New hash: {new_hash}")
            return new_hash, new_msg
    return None

# 手动计算 glue padding (不依赖 hashpumpy 时):
import struct

def md5_glue_padding(known_len):
    """MD5 glue padding for message of known_len bytes"""
    pad = b'\x80'
    pad += b'\x00' * ((55 - known_len) % 64)
    pad += struct.pack('<Q', known_len * 8)  # little-endian
    return pad

def sha256_glue_padding(known_len):
    """SHA256 glue padding for message of known_len bytes"""
    pad = b'\x80'
    pad += b'\x00' * ((55 - known_len) % 64)
    pad += struct.pack('>Q', known_len * 8)  # big-endian
    return pad

# 使用示例 (HTTP 场景)
# import requests
# def verify(h, msg):
#     r = requests.get(f'{URL}?data={msg.hex()}&mac={h}')
#     return 'success' in r.text
# hash_length_extension(known_hash, b'original', b';admin=true', verify)
```

---

### Template G: ECDSA Nonce Reuse → Private Key Recovery

两个签名使用相同 nonce k 时，可直接代数恢复私钥。

```python
#!/usr/bin/env python3
"""ECDSA nonce reuse — 恢复私钥"""
from hashlib import sha256

def recover_private_key_nonce_reuse(r, s1, s2, z1, z2, n):
    """两个签名 (r, s1) 和 (r, s2) 使用了相同的 nonce k
    r: 共同的 r 值 (因为 k 相同所以 r 相同)
    s1, s2: 两个 s 值
    z1, z2: 两个消息的 hash (截取低 n_bits 位)
    n: 曲线阶
    返回: 私钥 d
    """
    # k = (z1 - z2) / (s1 - s2) mod n
    k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n

    # d = (s1 * k - z1) / r mod n
    d = ((s1 * k - z1) * pow(r, -1, n)) % n

    # 验证: 也可以用 s2 计算
    d2 = ((s2 * k - z2) * pow(r, -1, n)) % n
    assert d == d2, "Verification failed — nonces might not be identical"

    return d

def hash_message(msg: bytes) -> int:
    """计算消息 hash (作为整数)"""
    return int(sha256(msg).hexdigest(), 16)

# 使用示例
# r = 0x...   (两个签名的 r 相同!)
# s1 = 0x...  (第一个签名)
# s2 = 0x...  (第二个签名)
# z1 = hash_message(msg1)
# z2 = hash_message(msg2)
# n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1
# private_key = recover_private_key_nonce_reuse(r, s1, s2, z1, z2, n)
```

---

### Template H: LLL Lattice Reduction (SageMath)

通用格攻击模板，适用于 knapsack、HNP、Coppersmith 等场景。

```python
#!/usr/bin/env sage
"""LLL 格攻击 — 通用模板 (Merkle-Hellman Knapsack 示例)"""
from sage.all import *

# ─── 场景 1: Merkle-Hellman 背包密码 ───
def knapsack_lll(public_key, target_sum):
    """用 LLL 解 subset sum: 找 x_i in {0,1} 使得 sum(x_i * pub[i]) = target
    public_key: 公钥列表 [w1, w2, ..., wn]
    target_sum: 密文 (子集和)
    """
    n = len(public_key)
    # 构造 (n+1) x (n+1) 格基矩阵
    M = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = 2
        M[i, n] = public_key[i]
    for i in range(n):
        M[n, i] = 1
    M[n, n] = target_sum

    L = M.LLL()
    for row in L:
        if row[-1] == 0 and all(abs(v) == 1 for v in row[:-1]):
            bits = [(1 - int(v)) // 2 for v in row[:-1]]
            if sum(b * w for b, w in zip(bits, public_key)) == target_sum:
                return bits
    return None

# ─── 场景 2: Hidden Number Problem (ECDSA partial nonce) ───
def hnp_attack(known_msb_list, signatures, n, num_bits_known):
    """HNP: 已知 nonce k 的高位 bits
    known_msb_list: 每个 nonce 的已知 MSB 值
    signatures: [(r_i, s_i, z_i), ...]
    n: 曲线阶
    num_bits_known: 已知的 MSB 位数
    完整实现参见 modules/advanced-math.md
    """
    m = len(signatures)
    B = 2^(n.nbits() - num_bits_known)
    M = Matrix(QQ, m + 2, m + 2)
    L = M.LLL()
    return L

# ─── 场景 3: 通用 CVP (Babai's Nearest Plane) ───
def solve_cvp(basis, target):
    """使用 Babai's nearest plane 求最近向量"""
    M = Matrix(ZZ, basis)
    G = M.gram_schmidt()[0]
    t = vector(ZZ, target)
    b = t
    for i in range(M.nrows() - 1, -1, -1):
        c = round(b.dot_product(G[i]) / G[i].dot_product(G[i]))
        b -= c * M[i]
    return t - b

# 使用示例
# plaintext_bits = knapsack_lll(pub_key, ciphertext)
```

---

## 工具参考 (Tool Reference)

### SageMath (密码学数学的瑞士军刀)

```bash
# 运行 SageMath 脚本
sage script.sage
# 或在 Python 中导入 Sage
sage -python script.py
```

```python
# 常用 SageMath 功能
from sage.all import *

# 因数分解
factor(n)                           # 分解整数
E = EllipticCurve(GF(p), [a, b])   # 椭圆曲线
E.order()                           # 曲线阶
G.discrete_log(Q)                   # 离散对数 (自动选算法)

# 多项式
R.<x> = PolynomialRing(Zmod(n))     # 模 n 多项式环
f = x^3 + a*x + b
f.small_roots(X=bound, beta=0.5)    # Coppersmith

# 矩阵/格
M = Matrix(ZZ, data)
M.LLL()                             # LLL 格基约简
berlekamp_massey(seq)               # LFSR 恢复

# 有限域
F = GF(p)                           # 素域
F = GF(2^8, 'a')                    # 扩展域
```

### RsaCtfTool

```bash
# 自动攻击 (推荐首选)
rsactftool --publickey pub.pem --private --attack all
# 指定参数
rsactftool -n $N -e $E --uncipher $C --attack all
# 常用攻击:
#   wiener, fermat, pastctfprimes, factordb, smallq, boneh_durfee
rsactftool --publickey pub.pem --private --attack wiener
```

### z3-solver

```python
from z3 import *

# BitVec: 固定宽度整数 (逆向/密码逻辑)
x = BitVec('x', 32)
s = Solver()
s.add(x ^ 0xdeadbeef == 0x12345678)
s.add(x > 0)
if s.check() == sat:
    print(s.model()[x])

# Int: 任意精度 (数论)
a, b = Ints('a b')
s.add(a * b == n, a > 1, b > 1)

# Real: 实数约束
# Bool: 布尔变量 (SAT 问题)
```

### factordb-pycli

```python
from factordb.factordb import FactorDB
f = FactorDB(n)
f.connect()
print(f.get_factor_list())  # [p, q] 或 [n] 如果未分解
print(f.get_status())       # 'FF'=完全分解, 'CF'=组合因子, 'P'=素数
```

### Python 常用库

| 库 | 用途 | 关键函数 |
|---|------|---------|
| `pycryptodome` | AES/RSA/DES 加解密 | `AES.new()`, `PKCS1_OAEP`, `long_to_bytes()` |
| `gmpy2` | 大数运算 | `iroot()`, `invert()`, `gcdext()`, `is_prime()` |
| `sympy` | 数论/代数 | `factorint()`, `nthroot_mod()`, `crt()`, `discrete_log()` |
| `galois` | 有限域/LFSR | `GF(2**8)`, `berlekamp_massey()` |
| `hashpumpy` | Hash 长度扩展 | `hashpump(hash, data, append, key_len)` |
| `pwntools` | 网络交互 | `remote()`, `xor()`, `p64()`/`u64()` |

### 命令行工具

| 工具 | 命令 | 用途 |
|------|------|------|
| rsactftool | `rsactftool --publickey pub.pem --private` | RSA 自动化攻击 |
| hashid | `hashid 'hash_value'` | Hash 类型识别 |
| hashcat | `hashcat -m 0 hash.txt wordlist` | GPU Hash 暴力破解 |
| john | `john --format=raw-md5 hash.txt` | CPU Hash 破解 |
| openssl | `openssl rsa -in pub.pem -pubin -text` | 查看密钥参数 |
| yafu | `yafu "factor(n)"` | 整数分解 |

### 在线资源

| 网站 | 用途 |
|------|------|
| factordb.com | 大整数分解查询 |
| quipqiup.com | 替换密码自动求解 |
| dcode.fr | 各类古典密码工具 |
| gchq.github.io/CyberChef | 编码转换 + 多步解密 |
| alpertron.com.ar/ECM.HTM | 在线 ECM 分解 |

---

## Module 详细参考

以下模块包含完整攻击代码和真实 CTF writeup。**本文件是调度入口，遇到具体问题务必 Read 对应 module 获取完整实现。**

| Module | 内容概要 | 何时 Read |
|--------|---------|----------|
| `modules/rsa-attacks.md` | RSA: small e, common modulus, Wiener, Pollard p-1, Hastad, Fermat, Coppersmith, Manger oracle, polynomial CRT | 看到 RSA 参数 (n/e/c) |
| `modules/rsa-attacks-2.md` | RSA 高级: batch GCD, dp/dq 恢复, CRT fault, 同态 oracle, p=q bypass, gcd(e,phi)>1 | RSA 基础攻击失败后 |
| `modules/rsa.md` | RSA 基础流程 (密钥生成, 分解方法列表) | RSA 入门参考 |
| `modules/modern-ciphers.md` | AES-CFB-8, ECB 泄漏, Padding Oracle, CBC-MAC, GCM nonce reuse, Bleichenbacher, MITM | AES/分组密码题 |
| `modules/modern-ciphers-2.md` | Hash 扩展, ECB byte-at-a-time, CBC IV bit-flip, MD5 fastcol, DES 弱密钥, Rabin LSB, SPN | Hash 攻击或高级 AES |
| `modules/stream-ciphers.md` | LFSR Berlekamp-Massey, 相关攻击, Galois LFSR, RC4 第二字节偏差, XOR 相关 | 流密码/LFSR 题 |
| `modules/prng.md` | MT19937 (untemper + z3), V8 XorShift128+, LCG, 时间种子, logistic map, ChaCha20 key recovery | PRNG 预测题 |
| `modules/ecc-attacks.md` | Smart's attack, 小子群, 无效曲线, ECDSA nonce reuse, Ed25519 torsion, DSA | ECC/ECDSA 题 |
| `modules/advanced-math.md` | LLL, Coppersmith, LWE/CVP, knapsack, isogeny, Pohlig-Hellman, 四元数 RSA, clock group | 格攻击/高级数学 |
| `modules/zkp-and-advanced.md` | Groth16, Z3 solver, Shamir SSS, garbled circuits, KZG, DV-SNARG, FROST, MAYO | ZKP/协议题 |
| `modules/classic-ciphers.md` | Vigenere Kasiski, XOR variants, OTP key reuse, 同音替换, grid permutation, book cipher | 古典密码题 |
| `modules/exotic-crypto.md` | Braid group DH, tropical semiring, Paillier, ElGamal, FPE Feistel, Goldwasser-Micali | 非标准密码体制 |
| `modules/historical.md` | Lorenz SZ40/42 cipher | 历史密码题 |

---

## 输出规范

```markdown
## 题目分析

**加密类型**: [RSA / AES-CBC / LFSR / ECDSA / ...]
**关键参数**: [n, e, c / key, iv, mode / ...]
**识别到的漏洞**: [具体漏洞名称 + 判断依据]

## 攻击方案

### Step 1: [阶段名称]
- 方法: ...
- 依据: ...

### Step 2: [阶段名称]
...

## Exploit 脚本

\`\`\`python
[完整可运行的解密脚本]
\`\`\`

## Flag

[解密得到的 flag]
```
