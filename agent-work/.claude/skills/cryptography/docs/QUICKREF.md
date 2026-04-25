# Crypto 快速参考

## RSA 攻击速查

| 条件 | 攻击方法 |
|------|----------|
| n 较小 | factordb 分解 |
| e = 3, m^3 < n | 直接开方 |
| 同 n 不同 e | 共模攻击 |
| d < n^0.25 | Wiener 攻击 |
| 同 m 不同 n | 广播攻击 (CRT) |
| 多个 n 共享因子 | GCD 分解 |
| 已知明文部分 | Coppersmith |

## 常用代码片段

### RSA 基础

```python
from Crypto.Util.number import *
import gmpy2

# 解密
phi = (p-1) * (q-1)
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

### 共模攻击

```python
g, s1, s2 = gmpy2.gcdext(e1, e2)
m = pow(c1, s1, n) * pow(c2, s2, n) % n
```

### 小指数攻击

```python
m = gmpy2.iroot(c, e)[0]
```

### 中国剩余定理

```python
from sympy.ntheory.modular import crt
m, _ = crt([n1, n2, n3], [c1, c2, c3])
```

## AES 速查

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# CBC 解密
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), 16)

# ECB 解密
cipher = AES.new(key, AES.MODE_ECB)
pt = unpad(cipher.decrypt(ct), 16)
```

## 古典密码

| 密码 | 特征 | 工具 |
|------|------|------|
| 凯撒 | 字母位移 | dcode.fr |
| 维吉尼亚 | 多表替换 | quipqiup |
| 栅栏 | 之字形排列 | dcode.fr |
| 培根 | AB 二进制 | dcode.fr |
| 摩尔斯 | 点划 | - |
| Base64 | = 结尾 | CyberChef |

## 数论工具

```python
import gmpy2

# 模逆
gmpy2.invert(a, m)

# GCD
gmpy2.gcd(a, b)

# 扩展欧几里得
gmpy2.gcdext(a, b)

# 开方
gmpy2.iroot(n, k)

# 素性测试
gmpy2.is_prime(n)
```

## 在线工具

- factordb.com - 大整数分解
- quipqiup.com - 替换密码
- dcode.fr - 各类密码
- gchq.github.io/CyberChef - 编码转换

## 命令行工具

```bash
# RsaCtfTool
python3 RsaCtfTool.py -n N -e E --uncipher C

# yafu 分解
yafu "factor(n)"

# openssl 读取公钥
openssl rsa -pubin -in pub.pem -text -noout
```
