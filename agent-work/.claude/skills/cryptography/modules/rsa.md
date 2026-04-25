# RSA 攻击完整流程

## RSA 基础知识

### 密钥生成

```python
# 1. 选择两个大素数 p, q
# 2. 计算 n = p * q
# 3. 计算 φ(n) = (p-1) * (q-1)
# 4. 选择 e，满足 gcd(e, φ(n)) = 1
# 5. 计算 d = e^(-1) mod φ(n)

# 公钥: (n, e)
# 私钥: (n, d) 或 (p, q, d)
```

### 加密解密

```python
# 加密: c = m^e mod n
# 解密: m = c^d mod n
```

## 攻击方法

### 1. 直接分解 n

```python
# 适用: n 较小或有特殊结构

# 方法 1: factordb
# http://factordb.com/

# 方法 2: yafu
# yafu "factor(n)"

# 方法 3: msieve
# msieve -q n

# 方法 4: Python (小 n)
from sympy import factorint
factors = factorint(n)
```

### 2. 小公钥指数攻击 (Low Public Exponent)

```python
# 适用: e 很小 (如 e=3)，且 m^e < n

import gmpy2
from Crypto.Util.number import long_to_bytes

# 直接开 e 次方根
m, is_perfect = gmpy2.iroot(c, e)
if is_perfect:
    print(long_to_bytes(m))
```

### 3. 小公钥指数 + 爆破

```python
# 适用: e 很小，m^e 略大于 n

import gmpy2
from Crypto.Util.number import long_to_bytes

for k in range(10000):
    m, is_perfect = gmpy2.iroot(c + k * n, e)
    if is_perfect:
        print(f"k = {k}")
        print(long_to_bytes(m))
        break
```

### 4. 共模攻击 (Common Modulus Attack)

```python
# 适用: 同一明文用相同 n、不同 e 加密

import gmpy2
from Crypto.Util.number import long_to_bytes

def common_modulus_attack(n, e1, e2, c1, c2):
    # 扩展欧几里得: e1*s1 + e2*s2 = gcd(e1, e2) = 1
    g, s1, s2 = gmpy2.gcdext(e1, e2)

    # 处理负指数
    if s1 < 0:
        c1 = gmpy2.invert(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = gmpy2.invert(c2, n)
        s2 = -s2

    # m = c1^s1 * c2^s2 mod n
    m = pow(c1, s1, n) * pow(c2, s2, n) % n
    return long_to_bytes(m)

# 使用
m = common_modulus_attack(n, e1, e2, c1, c2)
print(m)
```

### 5. Wiener 攻击 (低解密指数)

```python
# 适用: d < n^0.25 / 3

# 使用连分数展开 e/n 来恢复 d

def wiener_attack(e, n):
    # 连分数展开
    def continued_fraction(num, den):
        cf = []
        while den:
            cf.append(num // den)
            num, den = den, num % den
        return cf

    # 收敛子
    def convergents(cf):
        convs = []
        for i in range(len(cf)):
            if i == 0:
                convs.append((cf[0], 1))
            elif i == 1:
                convs.append((cf[0]*cf[1]+1, cf[1]))
            else:
                convs.append((
                    cf[i]*convs[-1][0] + convs[-2][0],
                    cf[i]*convs[-1][1] + convs[-2][1]
                ))
        return convs

    cf = continued_fraction(e, n)
    convs = convergents(cf)

    for k, d in convs:
        if k == 0:
            continue
        # 检验 d 是否正确
        if (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            # 解方程 x^2 - (n - phi + 1)x + n = 0
            b = n - phi + 1
            delta = b * b - 4 * n
            if delta >= 0:
                sqrt_delta = gmpy2.isqrt(delta)
                if sqrt_delta * sqrt_delta == delta:
                    return d
    return None

# 使用
d = wiener_attack(e, n)
if d:
    m = pow(c, d, n)
    print(long_to_bytes(m))
```

### 6. Boneh-Durfee 攻击

```python
# 适用: d < n^0.292
# 需要使用 SageMath

# SageMath 脚本
"""
load('boneh_durfee.sage')
d = boneh_durfee(e, n)
"""
```

### 7. 广播攻击 (Hastad's Broadcast Attack)

```python
# 适用: 同一明文用相同 e、不同 n 加密给多人

from sympy.ntheory.modular import crt
import gmpy2

# 中国剩余定理
def broadcast_attack(ns, cs, e):
    # 使用 CRT 合并
    N = 1
    for n in ns:
        N *= n

    result = 0
    for i in range(len(ns)):
        Ni = N // ns[i]
        Mi = gmpy2.invert(Ni, ns[i])
        result += cs[i] * Ni * Mi

    result = result % N
    m, _ = gmpy2.iroot(result, e)
    return m

# 使用 (e=3, 3 组密文)
m = broadcast_attack([n1, n2, n3], [c1, c2, c3], 3)
print(long_to_bytes(m))
```

### 8. 因子碰撞攻击

```python
# 适用: 多个 n 共享因子

import math

def find_common_factor(n1, n2):
    return math.gcd(n1, n2)

# 如果 gcd(n1, n2) > 1，则找到了共同因子
p = find_common_factor(n1, n2)
if p > 1:
    q1 = n1 // p
    q2 = n2 // p
    # 可以分别解密
```

### 9. Coppersmith 攻击

```python
# 适用: 已知明文高位或低位

# SageMath 脚本
"""
# 已知明文高位
def coppersmith_high_bits(n, e, c, known_high, unknown_bits):
    P.<x> = PolynomialRing(Zmod(n))
    f = (known_high + x)^e - c
    roots = f.small_roots(X=2^unknown_bits, beta=1)
    return roots

# 已知明文低位
def coppersmith_low_bits(n, e, c, known_low, unknown_bits):
    P.<x> = PolynomialRing(Zmod(n))
    f = (x * 2^len(bin(known_low)[2:]) + known_low)^e - c
    roots = f.small_roots(X=2^unknown_bits, beta=1)
    return roots
"""
```

### 10. 部分私钥泄露

```python
# 适用: 已知 d 的部分位

# SageMath 脚本
"""
def partial_d_attack(n, e, d_low, known_bits):
    # 使用 Coppersmith 方法恢复完整 d
    pass
"""
```

## 工具使用

### RsaCtfTool

```bash
# 安装
git clone https://github.com/Ganapati/RsaCtfTool
cd RsaCtfTool
pip3 install -r requirements.txt

# 使用
python3 RsaCtfTool.py -n N -e E --uncipher C
python3 RsaCtfTool.py --publickey key.pub --uncipherfile flag.enc
python3 RsaCtfTool.py -n N -e E --attack wiener
```

### 读取公钥文件

```python
from Crypto.PublicKey import RSA

# 读取 PEM 格式公钥
with open('public.pem', 'r') as f:
    key = RSA.import_key(f.read())
    n = key.n
    e = key.e

# 读取 DER 格式
with open('public.der', 'rb') as f:
    key = RSA.import_key(f.read())
```

## 完整利用模板

```python
#!/usr/bin/env python3
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
import gmpy2

# 读取参数
n = 0x...
e = 65537
c = 0x...

# 尝试 factordb 分解
# 如果成功，得到 p, q
p = ...
q = n // p

# 计算私钥
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)

# 解密
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag)
```

## 常见问题

### 大整数处理

```python
# 十六进制字符串转整数
n = int("0x...", 16)

# bytes 转整数
n = bytes_to_long(b'...')

# 整数转 bytes
m = long_to_bytes(n)
```

### 模运算

```python
import gmpy2

# 模逆
d = gmpy2.invert(e, phi)

# 模幂
c = pow(m, e, n)

# 开方
root, is_perfect = gmpy2.iroot(n, 2)
```
