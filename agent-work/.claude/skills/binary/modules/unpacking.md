# 脱壳与反混淆模块

## 适用场景
- UPX 标准/变种脱壳
- 自定义壳的运行时 dump
- 混淆二进制还原
- 加壳检测与判断

## 检查清单

```yaml
加壳检测:
  - [ ] binwalk -E 熵值分析（整体高熵 = 可能加壳）
  - [ ] readelf -S 检查段名（UPX0/UPX1 = UPX壳）
  - [ ] strings 检查壳标记（UPX!、ASPack、Themida）
  - [ ] file 输出是否异常（stripped + 很大 = 可能加壳）
  - [ ] 对比文件大小和 .text 段大小

UPX 脱壳:
  - [ ] upx -d 标准脱壳
  - [ ] 若失败 → 检查 UPX 魔数是否被篡改
  - [ ] 若篡改 → 修复魔数后重试
  - [ ] 若仍失败 → 运行时 dump

通用脱壳:
  - [ ] GDB 在 OEP 处断点 → dump
  - [ ] /proc/pid/mem dump
  - [ ] gcore 生成 core dump
  - [ ] 动态跟踪绕过脱壳（直接分析行为）
```

## 分析流程

### Step 1: 加壳检测

```bash
# 1. 熵值分析（高熵 = 压缩/加密）
binwalk -E ./target
# 如果大部分区域熵值 > 0.9，很可能加壳

# 2. 段名检查
readelf -S ./target | grep -iE 'UPX|PACK|PROTECT|VMProtect|themida'

# 3. 文件标记搜索
strings ./target | grep -iE 'UPX|ASPack|PECompact|Armadillo|Themida|VMProtect'

# 4. 快速判断 UPX
readelf -S ./target | grep 'UPX'
# 如果看到 UPX0 和 UPX1 段 → 确认 UPX 壳

# 5. 文件大小 vs 段大小对比
readelf -S ./target | grep '\.text'
ls -la ./target
# 如果 .text 段很小但文件很大（或反过来），可能加壳

# 6. PE 文件（Windows）
strings ./target | grep -iE 'UPX|Borland|MASM|NSIS|Inno|InstallShield'
# 也可以用 python pefile 库分析
```

### Step 2: UPX 标准脱壳

```bash
# 直接脱壳（90% 的 UPX 壳可以这样脱）
upx -d ./target -o ./target_unpacked

# 验证脱壳成功
file ./target_unpacked
readelf -S ./target_unpacked | grep -c UPX  # 应该为 0
strings ./target_unpacked | wc -l           # 应该比壳前多很多

# 如果报错 NotPackedException 或 CantUnpackException
# → 进入 Step 3（UPX 变种处理）
```

### Step 3: UPX 变种处理

#### 3.1 UPX 魔数修复

```python
#!/usr/bin/env python3
"""修复被篡改的 UPX 魔数"""

import sys
import struct

def find_upx_magic(data):
    """查找所有 UPX 相关标记的位置"""
    markers = {
        b'UPX!': 'UPX magic',
        b'UPX0': 'UPX segment 0',
        b'UPX1': 'UPX segment 1',
        b'UPX2': 'UPX segment 2',
    }
    found = {}
    for marker, desc in markers.items():
        positions = []
        start = 0
        while True:
            idx = data.find(marker, start)
            if idx == -1:
                break
            positions.append(idx)
            start = idx + 1
        if positions:
            found[marker] = (desc, positions)
    return found

def fix_upx_binary(input_path, output_path):
    """修复常见的 UPX 魔数篡改"""
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    found = find_upx_magic(data)
    print(f"[*] File size: {len(data)} bytes")
    print(f"[*] Existing markers:")
    for marker, (desc, positions) in found.items():
        for pos in positions:
            print(f"    {desc} at offset {hex(pos)}")

    # 常见篡改 1: 段名被修改（UPX0 → XXX0）
    # 修复 ELF section headers 中的段名
    for i in range(len(data) - 3):
        # 查找可能被篡改的 UPX 段名（保留数字后缀）
        if data[i+3:i+4] in (b'0', b'1', b'2'):
            # 检查前 3 字节是否看起来被修改
            if data[i:i+3] != b'UPX' and data[i:i+4] not in (b'.bss', b'.tex', b'.dat', b'.got', b'.plt', b'.rel', b'.dyn', b'.ini', b'.fin', b'.not', b'.sym', b'.str', b'.com', b'.gnu', b'.int', b'.ehs', b'.shm'):
                context = data[max(0,i-10):i+20]
                # 启发式：如果在 section name 区域附近
                if b'\x00' in data[max(0,i-4):i]:
                    print(f"    Possible tampered UPX{data[i+3]:c} at {hex(i)}: {context}")

    # 常见篡改 2: p_info 结构中的 UPX! 被清零或修改
    # UPX! 应该出现在文件末尾附近
    if b'UPX!' not in data:
        print("[!] No UPX! magic found — attempting repair")
        # 搜索 UPX loader 的特征模式
        # UPX 在文件末尾有一个 packheader: UPX! + version + format
        # 尝试恢复
        for i in range(len(data) - 32, max(0, len(data) - 1024), -1):
            # packheader 通常在文件末尾几百字节内
            # 前后有特征字节模式
            if data[i:i+1] == b'\x00' and data[i+4:i+5] in (b'\x0d', b'\x0e', b'\x0f', b'\x10'):
                # 可能是被清零的 UPX! 位置
                print(f"    Trying to restore UPX! at offset {hex(i)}")
                data[i:i+4] = b'UPX!'
                break

    # 修复 ELF 段名中的 UPX
    # 搜索 shstrtab 段
    if data[:4] == b'\x7fELF':
        is_64 = data[4] == 2
        if is_64:
            e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
            e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
            e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
            e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
            shstr_offset = struct.unpack_from('<Q', data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
        else:
            e_shoff = struct.unpack_from('<I', data, 0x20)[0]
            e_shentsize = struct.unpack_from('<H', data, 0x2E)[0]
            e_shnum = struct.unpack_from('<H', data, 0x30)[0]
            e_shstrndx = struct.unpack_from('<H', data, 0x32)[0]
            shstr_offset = struct.unpack_from('<I', data, e_shoff + e_shstrndx * e_shentsize + 0x10)[0]

        # 在 shstrtab 中修复段名
        for i in range(e_shnum):
            sh_entry = e_shoff + i * e_shentsize
            sh_name_idx = struct.unpack_from('<I', data, sh_entry)[0]
            name_start = shstr_offset + sh_name_idx
            name_end = data.index(b'\x00', name_start)
            name = data[name_start:name_end]

            # 检测被篡改的段名（3 字节 + 数字）
            if len(name) == 4 and name[3:4] in (b'0', b'1', b'2') and name[:3] != b'UPX':
                print(f"    Fixing section name at {hex(name_start)}: {name} -> UPX{name[3]:c}")
                data[name_start:name_start+3] = b'UPX'

    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"[+] Fixed binary written to {output_path}")

    # 尝试脱壳
    import subprocess
    result = subprocess.run(['upx', '-d', output_path, '-o', output_path + '.unpacked'],
                          capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] Successfully unpacked to {output_path}.unpacked")
    else:
        print(f"[-] UPX unpack failed: {result.stderr}")
        print("[*] Try runtime dump instead (Step 4)")

if __name__ == '__main__':
    fix_upx_binary(sys.argv[1], sys.argv[1] + '.fixed')
```

### Step 4: 运行时 dump（通用方案）

#### 4.1 GDB dump

```bash
# 方法 1: 在 main 处断点后 dump
gdb -batch \
    -ex 'b main' \
    -ex 'r' \
    -ex 'info proc mappings' \
    -ex 'dump binary memory /tmp/text.bin 0x400000 0x500000' \
    ./target

# 方法 2: 用 GDB 生成 core dump
gdb -batch \
    -ex 'b main' \
    -ex 'r' \
    -ex 'gcore /tmp/core_dump' \
    ./target

# 从 core dump 提取信息
strings /tmp/core_dump | grep -iE 'flag|key|secret'
```

#### 4.2 /proc 内存 dump

```bash
# 后台运行目标
./target &
PID=$!
sleep 1

# 查看内存映射
cat /proc/$PID/maps

# dump 所有可读内存段
python3 << 'EOF'
import re
import sys

pid = sys.argv[1] if len(sys.argv) > 1 else input("PID: ")

with open(f'/proc/{pid}/maps', 'r') as f:
    maps = f.readlines()

with open(f'/proc/{pid}/mem', 'rb') as mem:
    for line in maps:
        m = re.match(r'([0-9a-f]+)-([0-9a-f]+)\s+([rwxp-]+)', line)
        if m and 'r' in m.group(3):
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            size = end - start
            if size > 10 * 1024 * 1024:  # 跳过 > 10MB 的段
                continue
            try:
                mem.seek(start)
                data = mem.read(size)
                # 搜索关键信息
                for match in re.finditer(rb'flag\{[^\}]+\}', data):
                    print(f"  FOUND FLAG at {hex(start + match.start())}: {match.group()}")
                for match in re.finditer(rb'[\x20-\x7e]{20,}', data):
                    s = match.group().decode('latin-1')
                    if any(kw in s.lower() for kw in ['flag', 'key', 'secret', 'password', 'token']):
                        print(f"  Interesting string at {hex(start + match.start())}: {s[:200]}")
            except:
                pass
EOF

kill $PID
```

#### 4.3 gcore（需要 gdb）

```bash
# 最简单的 full dump
./target &
PID=$!
sleep 2
gcore -o /tmp/dump $PID
kill $PID

# 分析 core dump
strings /tmp/dump.$PID | grep -iE 'flag|key|secret|http'
```

### Step 5: 其他壳类型

#### VMProtect / Themida

```yaml
特征:
  - 极高的代码段熵值
  - 虚拟机指令解释器
  - 大量间接跳转
  - 代码膨胀明显

策略:
  - 不要试图完全脱壳（极难）
  - 动态跟踪 + 行为分析为主
  - strace/ltrace 获取程序行为
  - frida hook 关键函数
  - 内存搜索运行时解密的字符串
```

#### 自定义压缩壳

```yaml
特征:
  - 无已知壳标记
  - 有明显的解压 stub（入口点代码很短）
  - mprotect 调用（修改内存权限为可执行）
  - 可能有 mmap 匿名映射

策略:
  1. strace 跟踪 mprotect/mmap 调用
  2. 在 mprotect 之后断点（此时代码已解压）
  3. dump 新的可执行内存区域
  4. 重建 ELF 头
```

```bash
# 跟踪内存权限变更（壳在解压后会设置 PROT_EXEC）
strace -f -e trace=mprotect,mmap -s 500 ./target 2>&1

# 示例输出:
# mprotect(0x7f1234000000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) = 0
# → 这个地址区域包含解压后的代码
```

## 不脱壳的分析策略

有时脱壳不必要，直接分析运行时行为更高效：

```bash
# 1. 行为分析三件套
strace -f -s 500 -o /tmp/strace.log ./target
ltrace -f -s 200 -o /tmp/ltrace.log ./target 2>/dev/null
strings /tmp/strace.log | grep -iE 'connect|open|flag|key|secret'

# 2. 运行时字符串搜索
./target &
PID=$!
sleep 2
strings /proc/$PID/mem 2>/dev/null | grep -iE 'flag|key|secret'
# 或
gdb -batch -ex 'attach '$PID -ex 'gcore /tmp/rt_dump' -ex 'detach'
strings /tmp/rt_dump | grep -iE 'flag|key|secret'
kill $PID
```

## 脱壳后处理

```bash
# 1. 验证脱壳成功
file ./unpacked
readelf -S ./unpacked     # 段表是否正常
strings ./unpacked | wc -l  # 字符串数量应增加

# 2. 重新分析
checksec ./unpacked
strings ./unpacked | grep -iE 'flag|key|secret'
nm ./unpacked 2>/dev/null | head -50

# 3. 如果脱壳后无法运行（段表损坏）
# 不影响静态分析（strings/objdump 仍可用）
# 动态分析使用原始加壳版本
```

## 工具速查

```bash
# 检测
binwalk -E ./target              # 熵值分析
readelf -S ./target | grep UPX   # UPX 段检查
strings ./target | grep UPX      # UPX 标记

# UPX 脱壳
upx -d ./target -o ./unpacked    # 标准脱壳
upx -t ./target                  # 测试是否 UPX

# 运行时 dump
gdb -batch -ex 'b main' -ex 'r' -ex 'gcore /tmp/dump' ./target
gcore -o /tmp/dump $PID          # 需要先获取 PID
```
