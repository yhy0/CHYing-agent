---
category: crypto
tags: [rsa, factorization, wiener, coppersmith, hastad, broadcast, common_modulus, small_e, batch_gcd, n, e, c, p, q, phi, 公钥, 私钥, 因数分解, 小指数, 共模攻击, 广播攻击]
triggers: [rsa, public key, private key, n e c, p q, factordb, wiener, coppersmith, small_roots, hastad, broadcast attack, common modulus, batch gcd, RsaCtfTool, 公钥, 因数分解, 大整数分解, pem, der]
related: [padding_oracle, aes_ecb, hash_extension]
---

# RSA 基础与常见攻击

## 什么时候用

题目给出 RSA 公钥参数（n, e）和密文 c，要求恢复明文。RSA 是 CTF crypto 最高频的题型，几乎所有 crypto 方向必须掌握。

## 前提条件

- **已知公钥参数**：至少知道 n 和 e（或提供 `.pem`/`.der` 公钥文件）
- **已知密文 c**：需要解密的目标
- **存在弱点**：n 可分解、e 过小、d 过小、多组密文等

## 攻击步骤

### 1. 读取公钥与基本解密

从 PEM 文件提取参数，已知 p、q 时直接解密：

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
import gmpy2

# 读取公钥
with open('public.pem', 'r') as f:
    key = RSA.import_key(f.read())
    n, e = key.n, key.e

# 已知 p, q 时直接解密
p, q = ...  # 分解得到
phi = (p - 1) * (q - 1)
d = int(gmpy2.invert(e, phi))
m = pow(c, d, n)
print(long_to_bytes(m))
```

### 2. 分解 n（factordb / yafu / sympy）

n 较小或有特殊结构时，直接尝试分解：

```bash
# factordb 在线查询
# http://factordb.com/

# yafu 本地分解
yafu "factor(n_value)"

# RsaCtfTool 一键尝试所有攻击
python3 RsaCtfTool.py -n N -e E --uncipher C
python3 RsaCtfTool.py --publickey key.pub --uncipherfile flag.enc
```

```python
# Python 小 n 分解
from sympy import factorint
factors = factorint(n)  # 返回 {p1: e1, p2: e2, ...}
```

### 3. 小公钥指数攻击（e=3 直接开根）

当 e 很小（如 e=3）且 m^e < n 时，密文就是 m^e，直接开 e 次方根：

```python
import gmpy2

m, is_perfect = gmpy2.iroot(c, e)
if is_perfect:
    print(long_to_bytes(int(m)))
else:
    # m^e 略大于 n，爆破 k
    for k in range(10000):
        m, ok = gmpy2.iroot(c + k * n, e)
        if ok:
            print(long_to_bytes(int(m)))
            break
```

### 4. 共模攻击（同 n 不同 e）

同一明文用相同 n、不同 e 加密两次，且 gcd(e1, e2)=1：

```python
def common_modulus_attack(n, e1, e2, c1, c2):
    g, s1, s2 = gmpy2.gcdext(e1, e2)
    assert g == 1, "e1 和 e2 必须互素"
    if s1 < 0:
        c1 = int(gmpy2.invert(c1, n))
        s1 = -s1
    if s2 < 0:
        c2 = int(gmpy2.invert(c2, n))
        s2 = -s2
    m = pow(c1, int(s1), n) * pow(c2, int(s2), n) % n
    return long_to_bytes(m)
```

### 5. Wiener 攻击（d 过小）

当 d < N^0.25 时，e/n 的连分数展开可恢复 d。特征：e 非常大，接近 n：

```python
def wiener_attack(e, n):
    def continued_fraction(num, den):
        cf = []
        while den:
            q, r = divmod(num, den)
            cf.append(q)
            num, den = den, r
        return cf

    def convergents(cf):
        h0, h1, k0, k1 = 0, 1, 1, 0
        for a in cf:
            h0, h1 = h1, a * h1 + h0
            k0, k1 = k1, a * k1 + k0
            yield h1, k1

    from math import isqrt
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0:
            t = isqrt(disc)
            if t * t == disc:
                return d
    return None

# 也可以直接: pip install owiener
import owiener
d = owiener.attack(e, n)
```

### 6. Hastad 广播攻击（同 m 同 e 不同 n）

同一明文用 e 个不同公钥加密，CRT 合并后开根：

```python
from functools import reduce

def hastad_broadcast(cs, ns, e):
    N = reduce(lambda a, b: a * b, ns)
    result = 0
    for ci, ni in zip(cs, ns):
        Ni = N // ni
        Mi = pow(Ni, -1, ni)
        result += ci * Ni * Mi
    me = result % N
    m, ok = gmpy2.iroot(me, e)
    assert ok, "开根失败，可能密文组数不够"
    return long_to_bytes(int(m))

# e=3 时需要 3 组 (n, c)
m = hastad_broadcast([c1, c2, c3], [n1, n2, n3], 3)
```

### 7. Coppersmith 小根攻击（SageMath）

已知明文部分位时，用 SageMath 的 `small_roots` 恢复未知部分：

```python
# SageMath 脚本
n = ...
e = 3
c = ...
known_high = 0x666c61670000000000000000  # 已知高位
unknown_bits = 48  # 未知低位的比特数

P.<x> = PolynomialRing(Zmod(n))
f = (known_high + x)^e - c
roots = f.small_roots(X=2^unknown_bits, beta=1.0, epsilon=0.03)
if roots:
    m = known_high + int(roots[0])
    print(bytes.fromhex(hex(m)[2:]))
```

### 8. Batch GCD（多个 n 共享因子）

多个公钥的 n 可能共享素因子：

```python
from math import gcd
from functools import reduce

def batch_gcd(ns):
    """找出共享因子的 n 对"""
    results = {}
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            g = gcd(ns[i], ns[j])
            if g > 1 and g != ns[i]:
                results[i] = (g, ns[i] // g)
                results[j] = (g, ns[j] // g)
    return results

# 更高效的做法: 乘积树 + 余数树，O(n log^2 n)
```

## 常见坑

- **long_to_bytes 输出乱码**：多半 libc 版本（即 p、q）不对，或 e/phi 不互素。先检查 `gcd(e, phi) == 1`。
- **e 和 phi 不互素**：`gcd(e, (p-1)*(q-1)) > 1` 时标准求逆不行，需用 `e-th root mod p` 和 `e-th root mod q` 再 CRT 合并。SageMath: `Zmod(p)(c_p).nth_root(e, all=True)`。
- **Multi-prime RSA**：n = p1 * p2 * ... * pk，phi 要用 `product((pi-1) * pi^(ei-1))`，不是简单 `(p-1)*(q-1)`。
- **Coppersmith 参数调优**：`small_roots` 对 `X`（未知根上界）、`beta`（因子大小比）、`epsilon` 敏感。根找不到时试调 epsilon 从 0.01 到 0.1。
- **RsaCtfTool 依赖问题**：gmpy2 安装需要 `libgmp-dev`，SageMath 攻击需要独立安装 sage。
- **Fermat 分解漏掉**：p 和 q 接近时（`|p-q|` 小），从 sqrt(n) 附近搜索即可分解，yafu 自动尝试。
- **十六进制前缀**：`long_to_bytes` 结果开头有 `\x00` 时不影响 flag，但解析时注意编码。

## 变体

### Fermat 分解（p ≈ q）
p 和 q 非常接近时，从 isqrt(n) 开始搜索：
```python
a = gmpy2.isqrt(n) + 1
while True:
    b2 = a * a - n
    b = gmpy2.isqrt(b2)
    if b * b == b2:
        p, q = int(a + b), int(a - b)
        break
    a += 1
```

### Pollard p-1 分解
p-1 的所有因子都很小（B-smooth）时有效：
```python
def pollard_p1(n, B=100000):
    a = 2
    for j in range(2, B + 1):
        a = pow(a, j, n)
        g = gcd(a - 1, n)
        if 1 < g < n:
            return g, n // g
```

### Boneh-Durfee 攻击
d < N^0.292 时比 Wiener 更强，需 SageMath 运行 `boneh_durfee.sage`。

## 相关技术

- [[padding_oracle]] — RSA-OAEP / PKCS#1 v1.5 padding oracle 攻击
- [[aes_ecb]] — 对称加密攻击，题目常与 RSA 混合出现
- [[hash_extension]] — 哈希扩展攻击，MAC 绕过
