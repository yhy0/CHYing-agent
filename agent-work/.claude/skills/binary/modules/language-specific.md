# 特定语言编译产物逆向模块

## 适用场景
- Go 二进制分析（符号恢复、字符串提取、goroutine 识别）
- Rust 二进制分析（panic handler、mangled 符号、错误处理）
- C++ 二进制分析（vtable、RTTI、异常处理）
- .NET/Java 反编译
- Python/JavaScript 打包产物分析

## 语言识别速查

```bash
# 快速判断编译语言
file ./target                                                    # 基本信息

# Go 特征
strings ./target | grep -c 'runtime\.'                          # Go runtime
strings ./target | grep -c 'go.buildid'                         # Go build ID
strings ./target | grep 'runtime.main'                          # Go main
readelf -S ./target | grep -c '\.gopclntab\|\.go\.buildinfo'    # Go 特有段

# Rust 特征
strings ./target | grep -c 'core::result'                       # Rust core
strings ./target | grep -c 'std::panicking'                     # Rust panic
strings ./target | grep 'rust_begin_unwind\|rust_panic'         # Rust panic handler

# C++ 特征
strings ./target | grep -cE '_ZN|_ZS|_ZT'                      # C++ mangled symbols
readelf -S ./target | grep '.gcc_except_table'                  # C++ 异常表
nm ./target 2>/dev/null | grep -c 'typeinfo\|vtable'            # RTTI/vtable

# .NET
strings ./target | grep -c 'System\.\|Microsoft\.'             # .NET 命名空间
file ./target | grep -i 'Mono\|\.NET\|CIL'                     # .NET 标记

# Python (PyInstaller/cx_Freeze/Nuitka)
strings ./target | grep -iE 'pyinstaller\|python\|Py_Initialize'
binwalk ./target | grep -i 'python\|zlib'                       # PyInstaller 常用 zlib 压缩
```

---

## Go 二进制逆向

### 核心挑战

Go 二进制的特殊性：
1. **静态链接** — 包含完整 runtime，文件通常 > 5MB
2. **非 null 终止字符串** — Go 使用 `(pointer, length)` 结构，`strings` 命令会遗漏
3. **goroutine** — 并发执行，调用栈不同于传统线程
4. **interface/reflect** — 类型信息嵌入二进制
5. **符号保留** — 即使 stripped，`gopclntab` 段仍包含函数名

### 字符串提取

```bash
# 标准 strings（可能遗漏 Go 字符串）
strings -n 6 ./target | head -200

# Go 字符串表位于 .rodata 段，用 Python 提取
python3 << 'PYEOF'
import re

with open('./target', 'rb') as f:
    data = f.read()

# 方法 1: 暴力提取所有可打印序列
matches = set()
for m in re.finditer(rb'[\x20-\x7e]{6,}', data):
    matches.add(m.group())

# 方法 2: Go buildinfo 提取（版本和模块信息）
go_buildinfo_idx = data.find(b'\xff Go buildinf:')
if go_buildinfo_idx >= 0:
    print(f"[*] Go buildinfo at {hex(go_buildinfo_idx)}")
    # 后续字节包含 Go 版本
    info = data[go_buildinfo_idx:go_buildinfo_idx + 200]
    for m in re.finditer(rb'go[0-9]+\.[0-9]+(?:\.[0-9]+)?', info):
        print(f"    Go version: {m.group().decode()}")

# 方法 3: 按关键词过滤
keywords = ['flag', 'key', 'secret', 'password', 'token', 'http', 'https',
            'encrypt', 'decrypt', 'aes', 'config', 'api', '.com', '.net',
            '.org', 'aws', 'cloud', 'main.', 'func']

for s in sorted(matches, key=len, reverse=True):
    decoded = s.decode('latin-1')
    if any(kw in decoded.lower() for kw in keywords):
        print(f"  {decoded[:200]}")
PYEOF
```

### 符号恢复

```bash
# Go 保留的函数名（即使 stripped，gopclntab 仍有）
objdump -t ./target 2>/dev/null | grep 'main\.' | head -30      # main 包函数
objdump -t ./target 2>/dev/null | grep -v 'runtime\.' | head -50 # 非 runtime 函数

# 从 gopclntab 段提取函数名
readelf -S ./target | grep gopclntab
# 如果存在，可以用 go-tool 恢复完整符号

# radare2 分析 Go 二进制
r2 -A -q -c 'afl~main.' ./target       # main 包函数列表
r2 -A -q -c 'pdf @sym.main.main' ./target  # 反编译 main.main
```

### Go 特有分析工具

```bash
# go tool objdump（如果有 Go 环境）
go tool objdump ./target | grep 'main\.'

# redress（Go 二进制分析专用工具）
# https://github.com/goretk/redress
# redress -src ./target                  # 还原源码结构
# redress -pkg ./target                  # 包列表
# redress -type ./target                 # 类型信息

# GoReSym（Go 符号恢复）
# https://github.com/mandiant/GoReSym
# GoReSym -t ./target                    # 函数列表
```

### Go 网络函数关注点

```yaml
Go 网络相关函数名:
  HTTP 客户端:
    - net/http.(*Client).Do
    - net/http.(*Client).Get
    - net/http.(*Client).Post
    - net/http.(*Transport).roundTrip

  TLS:
    - crypto/tls.(*Conn).Handshake
    - crypto/tls.(*Conn).Write
    - crypto/tls.(*Conn).Read
    - crypto/tls.(*Config).serverInit

  DNS:
    - net.(*Resolver).lookupHost
    - net.(*Resolver).lookupIP

  TCP:
    - net.(*TCPConn).Write
    - net.(*TCPConn).Read
    - net.(*Dialer).DialContext

  加密:
    - crypto/aes.newCipher
    - crypto/cipher.NewGCM
    - crypto/rsa.EncryptPKCS1v15
```

---

## Rust 二进制逆向

### 核心挑战

1. **重度 mangled 符号** — 名称极长但包含完整路径信息
2. **零成本抽象** — 泛型展开导致函数数量膨胀
3. **panic 处理** — 错误路径暴露源码路径和行号
4. **所有权系统** — 编译后的代码中 drop 调用频繁

### 符号分析

```bash
# Rust mangled 符号解析
nm ./target 2>/dev/null | grep -v '__' | head -50

# 使用 rustfilt 解析（如果可用）
# nm ./target | rustfilt

# 手动解析 mangled 名称
# _ZN开头: C++ ABI
# _R开头: Rust v0 mangling
nm ./target 2>/dev/null | grep '_ZN.*main\|_R.*main'

# 提取 panic 信息（暴露源码路径）
strings ./target | grep -E 'src/|\.rs:'
# 示例输出: src/main.rs:42:5
# 这些路径泄露了项目结构！

# 错误消息（Rust 的 Display trait）
strings ./target | grep -iE 'error|panic|unwrap|expect|failed'
```

### Rust 特有分析

```bash
# 查找 main 函数
nm ./target 2>/dev/null | grep -i 'main'
# Rust main 通常在: 项目名::main

# 查找自定义类型（通过 RTTI 或 Debug trait）
strings ./target | grep -E '^[A-Z][a-z]+[A-Z]'  # CamelCase 类型名

# 依赖库识别
strings ./target | grep -E 'crates\.io|registry|Cargo'
```

---

## C++ 二进制逆向

### 核心挑战

1. **vtable** — 虚函数表是类继承的关键线索
2. **RTTI** — 运行时类型信息包含类名
3. **异常处理** — .gcc_except_table 暴露控制流
4. **模板展开** — 导致符号极其冗长
5. **STL 容器** — std::string、std::vector 等内部结构

### vtable 和 RTTI 分析

```bash
# 提取 RTTI 类型信息
strings ./target | grep 'typeinfo name for'
# 或
nm ./target 2>/dev/null | grep 'typeinfo' | head -20

# 提取 vtable（虚函数表 → 类层次结构）
nm ./target 2>/dev/null | grep 'vtable' | head -20

# C++ demangling
nm ./target 2>/dev/null | c++filt | head -50
# 或
nm -C ./target 2>/dev/null | head -50
```

### STL 容器识别

```yaml
std::string:
  - 内存布局: [pointer, size, capacity] 或 SSO
  - 搜索特征: 连续 3 个指针大小的值

std::vector:
  - 内存布局: [begin_ptr, end_ptr, capacity_ptr]

std::map:
  - 红黑树实现
  - 搜索特征: 左/右/父指针 + 颜色位

std::unordered_map:
  - 哈希表实现
  - 搜索特征: 桶数组 + 节点链表
```

---

## .NET 逆向

```bash
# 检测 .NET
file ./target | grep -i 'mono\|\.net\|CIL\|PE32.*CLR'
strings ./target | grep -c 'System\.'

# .NET 反编译工具
# dnSpy: GUI 反编译器（Windows）
# ILSpy: 开源反编译器
# dotnet-dump: CLI 工具

# Mono 环境下执行
mono ./target.exe

# 反编译 IL 代码
monodis ./target.exe > /tmp/il_code.txt
strings /tmp/il_code.txt | grep -iE 'flag|key|secret'
```

---

## Python 打包产物

### PyInstaller

```bash
# 检测 PyInstaller
strings ./target | grep -i 'pyinstaller\|PYZ\|PKG'
binwalk ./target | grep -i 'python\|zlib'

# 提取打包内容
# pyinstxtractor（Python 脚本）
python3 pyinstxtractor.py ./target
# 输出到 target_extracted/ 目录

# 或用 binwalk
binwalk -e ./target

# 反编译 .pyc 文件
# uncompyle6 / decompyle3 / pycdc
uncompyle6 target_extracted/main.pyc > main.py
# 或
pycdc target_extracted/main.pyc > main.py

# 手动提取（如果工具不可用）
python3 << 'EOF'
import struct

with open('./target', 'rb') as f:
    data = f.read()

# PyInstaller 在文件末尾有 MAGIC: 'MEI\014\013\012\013\016'
magic = b'MEI\x0c\x0b\x0a\x0b\x0e'
idx = data.find(magic)
if idx >= 0:
    print(f"[*] PyInstaller archive at offset {hex(idx)}")
    # 之前 24 字节是 CArchive 的 cookie
    cookie_start = idx - 24
    toc_offset = struct.unpack_from('<i', data, cookie_start)[0]
    toc_len = struct.unpack_from('<i', data, cookie_start + 4)[0]
    print(f"    TOC offset: {hex(toc_offset)}, length: {toc_len}")
else:
    print("[-] PyInstaller magic not found")
EOF
```

### cx_Freeze / Nuitka

```bash
# cx_Freeze: 通常有 library.zip
binwalk ./target | grep -i 'zip'
unzip -l extracted_library.zip

# Nuitka: 编译为 C 再编译为 native
# 更难反编译，但 strings 仍可能有有用信息
strings ./target | grep -iE 'flag|\.py|import|def |class '
```

---

## 语言特征速查表

```yaml
Go:
  file 输出: "Go BuildID="
  特有段: .gopclntab, .go.buildinfo, .noptrdata
  字符串: "runtime.", "go.buildid"
  符号: main.main, main.init
  运行时: goroutine stack, GC 相关

Rust:
  file 输出: 通常无特殊标记
  特有段: .rustc
  字符串: "core::result", "std::panicking", ".rs:" 路径
  符号: _ZN/_R 开头 mangled names
  特征: panic 信息包含源码位置

C++:
  file 输出: 通常无特殊标记
  特有段: .gcc_except_table, .eh_frame
  字符串: "typeinfo", "vtable for"
  符号: _ZN 开头 mangled names
  特征: c++filt 可解析

.NET:
  file 输出: "Mono/.Net assembly", "PE32.*CLR"
  特征: "System.*" 命名空间大量出现
  工具: monodis, dnSpy, ILSpy

Python (PyInstaller):
  file 输出: 可能显示 ELF/PE
  特征: "pyinstaller", "PYZ", "MEI\014" magic
  工具: pyinstxtractor, uncompyle6

Java (JAR/DEX):
  file 输出: "Java archive", "Dalvik dex"
  工具: jadx, cfr, procyon
  特征: class 文件, META-INF
```

## 工具速查

```bash
# Go
objdump -t target | grep 'main\.'        # 函数列表
strings target | grep 'runtime\.'         # 确认 Go
readelf -S target | grep gopclntab        # Go 特有段

# Rust
strings target | grep '\.rs:'            # 源码路径
nm target | c++filt                       # 符号解析

# C++
nm -C target | head -50                   # 解析符号
strings target | grep 'typeinfo'          # RTTI 类名

# .NET
monodis target.exe                        # IL 反编译

# Python
python3 pyinstxtractor.py target          # PyInstaller 提取
uncompyle6 main.pyc                       # .pyc 反编译
```
