# 静态分析模块

## 适用场景
- ELF/PE 二进制的反汇编与反编译
- 符号表分析、交叉引用、控制流还原
- 加密算法识别、字符串定位

## 检查清单

```yaml
基础检查:
  - [ ] file / readelf -h 确认架构和位数
  - [ ] checksec 检查保护机制
  - [ ] strings + grep 快速搜索关键字
  - [ ] nm / objdump -T 检查符号表

深入分析:
  - [ ] 入口点（entry point）定位
  - [ ] main 函数反编译
  - [ ] 关键函数交叉引用（xref）
  - [ ] 数据段（.data/.rodata/.bss）分析
  - [ ] 导入函数列表（判断功能）
  - [ ] 比较常量/magic number 识别算法

反编译工具选择:
  - Ghidra（无头模式）: 完整反编译，支持脚本自动化
  - radare2: 轻量快速，适合命令行环境
  - objdump + readelf: 系统自带，基础分析足够
  - IDA Free: 交互式，但需 GUI
```

## 分析流程

### Step 1: ELF 结构分析

```bash
# 文件头完整信息
readelf -h ./target

# 段表（Section headers）
readelf -S ./target
# 重点关注:
# .text    — 代码段
# .rodata  — 只读数据（字符串常量、加密密钥）
# .data    — 已初始化全局变量
# .bss     — 未初始化全局变量
# .got.plt — GOT 表（用于动态链接）
# .init    — 初始化代码
# .fini    — 终止代码

# 程序头（Segment headers）
readelf -l ./target

# 重定位信息
readelf -r ./target
```

### Step 2: 符号表分析

```bash
# 完整符号表
nm ./target 2>/dev/null | head -100

# 按类型过滤
nm ./target 2>/dev/null | grep ' T '   # 代码段函数
nm ./target 2>/dev/null | grep ' D '   # 数据段符号
nm ./target 2>/dev/null | grep ' U '   # 未定义（外部引用）

# 关键函数搜索
nm ./target 2>/dev/null | grep -iE 'main|init|start|key|flag|encrypt|decrypt|verify|check|auth|login|secret|password|c2|beacon|callback|send|recv'

# 动态符号
objdump -T ./target 2>/dev/null | head -50

# 导入函数分析（判断程序功能）
readelf --dyn-syms ./target 2>/dev/null | grep -i 'FUNC' | awk '{print $NF}'
# 网络相关: connect, send, recv, socket, getaddrinfo
# 加密相关: EVP_, AES_, SSL_, SHA_, MD5
# 文件相关: fopen, fread, opendir
# 进程相关: fork, exec, system, popen
```

### Step 3: 字符串深度分析

```bash
# 基础字符串
strings -n 6 ./target > /tmp/strings.txt
wc -l /tmp/strings.txt

# 分类搜索
grep -iE 'flag|ctf|key|secret' /tmp/strings.txt          # Flag 相关
grep -iE 'http|https|ftp|ws://' /tmp/strings.txt          # URL
grep -iE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /tmp/strings.txt  # IP
grep -iE 'aes|des|rsa|xor|rc4|blowfish' /tmp/strings.txt # 加密算法
grep -iE 'base64|hex|rot13|caesar' /tmp/strings.txt       # 编码
grep -iE 'error|fail|success|correct|wrong' /tmp/strings.txt # 逻辑分支

# 提取疑似 Base64 编码数据
grep -oE '[A-Za-z0-9+/]{20,}={0,2}' /tmp/strings.txt | while read line; do
    echo -n "$line -> "; echo "$line" | base64 -d 2>/dev/null; echo
done
```

### Step 4: 反汇编与反编译

#### objdump（系统自带）

```bash
# 完整反汇编
objdump -d ./target > /tmp/disasm.txt

# 只看 main 函数
objdump -d ./target | sed -n '/<main>/,/^$/p'

# 查看 .rodata 段（常量数据）
objdump -s -j .rodata ./target

# Intel 语法（更易读）
objdump -d -M intel ./target | head -200
```

#### radare2（如果可用）

```bash
# 快速分析
r2 -A -q -c 'afl' ./target            # 列出所有函数
r2 -A -q -c 'pdf @main' ./target      # 反编译 main
r2 -A -q -c 'axt @sym.encrypt' ./target  # 交叉引用
r2 -A -q -c 'iz' ./target             # 所有字符串
r2 -A -q -c 'iI' ./target             # 二进制信息
r2 -A -q -c 'ii' ./target             # 导入表
r2 -A -q -c 'ie' ./target             # 导出表

# 搜索特定字节序列
r2 -A -q -c '/x 666c6167' ./target    # 搜索 "flag" 的 hex
```

#### Ghidra 无头模式（如果可用）

```bash
# 自动分析并导出反编译结果
analyzeHeadless /tmp/ghidra_proj proj \
    -import ./target \
    -postScript ExportDecompiled.py \
    -scriptPath /path/to/scripts
```

## 常见算法识别

```yaml
通过常量识别:
  AES:
    - S-box: 0x63, 0x7c, 0x77, 0x7b...
    - Rcon: 0x01, 0x02, 0x04, 0x08...

  DES:
    - IP 表: 58, 50, 42, 34, 26...
    - S-box 特征常量

  MD5:
    - 初始值: 0x67452301, 0xefcdab89...
    - T 常量: 0xd76aa478, 0xe8c7b756...

  SHA-1:
    - 初始值: 0x67452301, 0xEFCDAB89...
    - K 常量: 0x5A827999, 0x6ED9EBA1...

  SHA-256:
    - 初始值: 0x6a09e667, 0xbb67ae85...
    - K 常量: 0x428a2f98, 0x71374491...

  RC4:
    - 256 字节 S-box 初始化循环
    - KSA + PRGA 模式

  TEA/XTEA:
    - Delta 常量: 0x9e3779b9
    - 32 轮循环

  Base64:
    - 字母表: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    - 注意自定义字母表变种

通过结构识别:
  XOR 加密:
    - 简单循环 + XOR 操作
    - 单字节 / 多字节密钥

  异或替换:
    - 256 字节查找表 + 逐字节替换

  自定义编码:
    - 移位 + 加减 + 异或组合
```

## 交叉引用分析

```bash
# 追踪关键函数调用链
# 1. 找到目标函数地址
nm ./target | grep 'encrypt'

# 2. 搜索该地址在代码中的引用
objdump -d ./target | grep 'call.*encrypt'

# 3. 使用 radare2 的交叉引用（更方便）
r2 -A -q -c 'axt @sym.encrypt' ./target
```

## 数据提取

```python
#!/usr/bin/env python3
"""从 ELF 中提取特定段的数据"""

import struct

def extract_section(binary_path, section_name):
    """提取指定段的原始数据"""
    with open(binary_path, 'rb') as f:
        data = f.read()

    # 解析 ELF header
    if data[:4] != b'\x7fELF':
        print("Not an ELF file")
        return None

    is_64bit = data[4] == 2

    if is_64bit:
        e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
        e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
        e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    else:
        e_shoff = struct.unpack_from('<I', data, 0x20)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x2E)[0]
        e_shnum = struct.unpack_from('<H', data, 0x30)[0]
        e_shstrndx = struct.unpack_from('<H', data, 0x32)[0]

    # 读取 section name string table
    if is_64bit:
        shstr_offset = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
        shstr_size = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 0x20)[0]
    else:
        shstr_offset = struct.unpack_from('<I', data, e_shoff + e_shstrndx * e_shentsize + 0x10)[0]
        shstr_size = struct.unpack_from('<I', data, e_shoff + e_shstrndx * e_shentsize + 0x14)[0]

    shstrtab = data[shstr_offset:shstr_offset + shstr_size]

    # 遍历 section headers
    for i in range(e_shnum):
        sh_entry = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from('<I', data, sh_entry)[0]
        name = shstrtab[sh_name_idx:shstrtab.index(b'\x00', sh_name_idx)].decode()

        if name == section_name:
            if is_64bit:
                sh_offset = struct.unpack_from('<Q', data, sh_entry + 0x18)[0]
                sh_size = struct.unpack_from('<Q', data, sh_entry + 0x20)[0]
            else:
                sh_offset = struct.unpack_from('<I', data, sh_entry + 0x10)[0]
                sh_size = struct.unpack_from('<I', data, sh_entry + 0x14)[0]

            return data[sh_offset:sh_offset + sh_size]

    return None

# 使用示例
rodata = extract_section('./target', '.rodata')
if rodata:
    print(f".rodata size: {len(rodata)} bytes")
    # 搜索可打印字符串
    import re
    for m in re.finditer(rb'[\x20-\x7e]{6,}', rodata):
        print(f"  {m.start():6x}: {m.group().decode('latin-1')}")
```

## 工具速查

```bash
# ELF 信息
file target                           # 基本信息
readelf -h target                     # ELF 头
readelf -S target                     # 段表
readelf -l target                     # 程序头
readelf --dyn-syms target             # 动态符号

# 符号
nm target                             # 符号表
nm -D target                          # 动态符号
nm target | grep ' T '               # 代码段函数

# 反汇编
objdump -d target                     # 完整反汇编
objdump -d -M intel target            # Intel 语法
objdump -s -j .rodata target          # 查看数据段

# 搜索
strings -n 6 target                   # 字符串提取
strings -el target                    # UTF-16 LE
grep -boa 'pattern' target            # 二进制 grep
```
