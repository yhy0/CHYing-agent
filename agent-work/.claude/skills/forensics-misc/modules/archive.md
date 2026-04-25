# 📦 压缩包分析模块

## 适用文件类型
- ZIP / RAR / 7Z / TAR / GZ / BZ2 / XZ

## 检查清单

```yaml
基础检查:
  - [ ] 文件类型识别（file）
  - [ ] 压缩包内容列表（不解压）
  - [ ] 注释字段检查
  - [ ] 文件头魔数验证
  - [ ] 压缩包完整性检查

ZIP 专项:
  - [ ] 伪加密检测（加密标志位）
  - [ ] CRC32 碰撞爆破（小文件）
  - [ ] 明文攻击（已知部分明文）
  - [ ] 密码爆破（字典攻击）
  - [ ] ZIP 注释提取
  - [ ] 多层套娃解压
  - [ ] ZIP64 格式检测
  - [ ] 损坏的 ZIP 修复

RAR 专项:
  - [ ] RAR 密码爆破
  - [ ] RAR 注释提取
  - [ ] 分卷压缩包合并
  - [ ] RAR 加密方式识别

7Z 专项:
  - [ ] 7Z 密码爆破
  - [ ] 7Z 头加密检测
  - [ ] 固实压缩检测

通用技巧:
  - [ ] 递归解压（套娃）
  - [ ] 文件名隐藏信息
  - [ ] 时间戳分析
  - [ ] 压缩率异常检测
  - [ ] NTFS 交换数据流（Windows）

常用工具:
  - unzip, 7z, rar, tar
  - fcrackzip (ZIP 密码爆破)
  - john, hashcat (通用密码爆破)
  - bkcrack (ZIP 明文攻击)
  - zipdetails (ZIP 结构分析)
  - rarcrack (RAR 密码爆破)
```

## 分析流程

### Step 1: 基础信息收集

```bash
# 文件类型
file archive.zip

# 查看压缩包内容（不解压）
unzip -l archive.zip
7z l archive.7z
rar l archive.rar
tar -tzf archive.tar.gz

# 查看详细信息
unzip -v archive.zip  # 显示 CRC32、压缩率等
7z l -slt archive.7z  # 详细信息

# 查看注释
unzip -z archive.zip
7z l -slt archive.7z | grep -i comment

# 检查文件头
xxd archive.zip | head -20
# ZIP: 50 4B 03 04
# RAR: 52 61 72 21
# 7Z: 37 7A BC AF 27 1C
```

### Step 2: ZIP 伪加密检测与修复

```bash
# 方法 1: 使用脚本自动修复
python3 scripts/zip_fake_encrypt.py archive.zip

# 方法 2: 手动检查
zipdetails archive.zip

# 查看加密标志位
# Local file header offset +6: General purpose bit flag
# Bit 0 = 1: 加密
# Bit 0 = 0: 未加密

# 方法 3: 十六进制编辑
xxd archive.zip | grep "504b 0304"
# 找到 Local file header
# Offset +6 的位置，如果是 09 00，改为 00 00
```

### Step 3: CRC32 碰撞爆破

```python
#!/usr/bin/env python3
"""CRC32 碰撞爆破 - 适用于小文件"""
import zipfile
import binascii
import itertools
import string

def crack_crc32(target_crc, max_length=6, charset=None):
    """
    爆破 CRC32
    target_crc: 目标 CRC32 值（整数）
    max_length: 最大长度
    charset: 字符集（默认: 数字+字母）
    """
    if charset is None:
        charset = string.ascii_letters + string.digits + string.punctuation
    
    for length in range(1, max_length + 1):
        print(f"[*] Trying length {length}...")
        for attempt in itertools.product(charset, repeat=length):
            data = ''.join(attempt).encode()
            if binascii.crc32(data) & 0xffffffff == target_crc:
                return data.decode()
    return None

# 从 ZIP 中获取 CRC32
with zipfile.ZipFile('archive.zip') as zf:
    for info in zf.infolist():
        print(f"File: {info.filename}")
        print(f"CRC32: {info.CRC:08x}")
        print(f"Size: {info.file_size} bytes")
        
        # 如果文件很小，尝试爆破
        if info.file_size <= 8:
            print(f"[*] Attempting CRC32 collision for {info.filename}...")
            result = crack_crc32(info.CRC, max_length=info.file_size)
            if result:
                print(f"[+] Found: {result}")
```

### Step 4: 密码爆破

```bash
# ZIP 密码爆破 - fcrackzip（快速）
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt archive.zip
fcrackzip -u -b -c 'aA1!' -l 1-6 archive.zip  # 暴力破解 1-6 位

# ZIP 密码爆破 - John the Ripper
zip2john archive.zip > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt  # 显示结果

# ZIP 密码爆破 - Hashcat（GPU 加速）
zip2john archive.zip > hash.txt
# 提取哈希（格式: $pkzip2$*...）
hashcat -m 17200 -a 0 hash.txt wordlist.txt
hashcat -m 17210 -a 0 hash.txt wordlist.txt  # PKZIP (Compressed)

# RAR 密码爆破
rar2john archive.rar > hash.txt
john --wordlist=wordlist.txt hash.txt

# 7Z 密码爆破
7z2john archive.7z > hash.txt
john --wordlist=wordlist.txt hash.txt
```

### Step 5: ZIP 明文攻击（bkcrack）

```bash
# 前提: 已知压缩包中某个文件的明文（至少 12 字节）

# 1. 创建包含已知明文的 ZIP
zip plain.zip known_file.txt

# 2. 执行明文攻击
bkcrack -C encrypted.zip -c target.txt -P plain.zip -p known_file.txt

# 3. 使用恢复的密钥解密
bkcrack -C encrypted.zip -k <key0> <key1> <key2> -D decrypted.zip

# 4. 或者恢复密码
bkcrack -C encrypted.zip -k <key0> <key1> <key2> -r 6 ?p

# 常见已知明文来源:
# - 题目中给出的文件
# - 标准文件头（PNG: 89 50 4E 47, JPG: FF D8 FF）
# - README.txt, flag.txt 等常见文件名
```

### Step 6: 递归解压（套娃）

```python
#!/usr/bin/env python3
"""递归解压套娃压缩包"""
import os
import zipfile
import rarfile
import py7zr
import shutil

def extract_recursive(filename, depth=0, max_depth=20):
    """递归解压"""
    if depth > max_depth:
        print(f"[!] Max depth {max_depth} reached")
        return
    
    print(f"{'  ' * depth}[*] Extracting: {filename}")
    
    # 创建临时目录
    extract_dir = f"extract_{depth}"
    os.makedirs(extract_dir, exist_ok=True)
    
    # 根据类型解压
    try:
        if filename.endswith('.zip'):
            with zipfile.ZipFile(filename) as zf:
                zf.extractall(extract_dir)
        elif filename.endswith('.rar'):
            with rarfile.RarFile(filename) as rf:
                rf.extractall(extract_dir)
        elif filename.endswith('.7z'):
            with py7zr.SevenZipFile(filename, 'r') as szf:
                szf.extractall(extract_dir)
    except Exception as e:
        print(f"{'  ' * depth}[!] Error: {e}")
        return
    
    # 检查提取的文件
    for root, dirs, files in os.walk(extract_dir):
        for file in files:
            filepath = os.path.join(root, file)
            print(f"{'  ' * depth}  Found: {file}")
            
            # 搜索 flag
            if 'flag' in file.lower():
                print(f"{'  ' * depth}  [+] Potential flag file: {file}")
            
            # 如果是压缩包，继续解压
            if file.endswith(('.zip', '.rar', '.7z')):
                extract_recursive(filepath, depth + 1, max_depth)

if __name__ == '__main__':
    import sys
    extract_recursive(sys.argv[1])
```

### Step 7: 高级分析

```python
# 1. ZIP 结构分析
import zipfile

with zipfile.ZipFile('archive.zip') as zf:
    for info in zf.infolist():
        print(f"Filename: {info.filename}")
        print(f"CRC32: {info.CRC:08x}")
        print(f"Compressed size: {info.compress_size}")
        print(f"Uncompressed size: {info.file_size}")
        print(f"Compression type: {info.compress_type}")
        print(f"Comment: {info.comment}")
        print(f"Date: {info.date_time}")
        print("-" * 40)

# 2. 检测异常压缩率
with zipfile.ZipFile('archive.zip') as zf:
    for info in zf.infolist():
        if info.file_size > 0:
            ratio = info.compress_size / info.file_size
            if ratio > 1.0:  # 压缩后反而变大
                print(f"[!] Suspicious: {info.filename} (ratio: {ratio:.2f})")
            elif ratio < 0.1:  # 压缩率极高
                print(f"[!] High compression: {info.filename} (ratio: {ratio:.2f})")

# 3. 提取所有注释
with zipfile.ZipFile('archive.zip') as zf:
    # ZIP 全局注释
    if zf.comment:
        print(f"ZIP Comment: {zf.comment.decode('utf-8', errors='ignore')}")
    
    # 文件注释
    for info in zf.infolist():
        if info.comment:
            print(f"{info.filename} Comment: {info.comment.decode('utf-8', errors='ignore')}")
```

## 常见出题套路与解法

### 套路 1: ZIP 伪加密

**特征**: 解压时提示需要密码，但实际未加密

**解法**:
```bash
python3 scripts/zip_fake_encrypt.py archive.zip
# 或手动修改加密标志位
```

**识别方法**:
- `zipdetails archive.zip` 查看 General purpose bit flag
- Bit 0 = 1 但实际没有加密数据

### 套路 2: CRC32 碰撞（小文件爆破）

**特征**: 压缩包中有很小的文件（1-8 字节）

**解法**:
```python
# 使用上面的 CRC32 爆破脚本
# 常见内容: 纯数字、纯字母、简单单词
```

**优化技巧**:
- 先尝试纯数字（0-9）
- 再尝试常见单词（flag, ctf, key）
- 最后尝试字母+数字组合

### 套路 3: 明文攻击

**特征**: 压缩包加密，但已知部分文件内容

**解法**:
```bash
# 使用 bkcrack
bkcrack -C encrypted.zip -c file.txt -P plain.zip -p file.txt
```

**常见已知明文**:
- 题目中给出的文件
- 标准文件头（PNG/JPG/PDF）
- README.txt 等常见文件

### 套路 4: 密码在文件名/注释中

**特征**: 密码隐藏在压缩包的元数据中

**解法**:
```bash
# 查看所有注释
unzip -z archive.zip
7z l -slt archive.7z | grep -i comment

# 查看文件名
unzip -l archive.zip

# 密码可能是:
# - 文件名的一部分
# - 文件名的 MD5/Base64
# - 注释字段的内容
```

### 套路 5: 多层套娃

**特征**: 压缩包里套压缩包，层层嵌套

**解法**:
```python
# 使用递归解压脚本
python3 extract_recursive.py archive.zip
```

**常见变体**:
- 100 层套娃（需要自动化）
- 每层密码不同（密码有规律）
- 最内层才是 flag

### 套路 6: 损坏的压缩包修复

**特征**: 压缩包无法正常解压，提示损坏

**解法**:
```bash
# ZIP 修复
zip -FF broken.zip --out fixed.zip

# RAR 修复
rar r broken.rar

# 手动修复文件头
xxd broken.zip | head
# 检查魔数是否正确: 50 4B 03 04
```

### 套路 7: 分卷压缩包

**特征**: 多个文件 .zip.001, .zip.002, ...

**解法**:
```bash
# 合并分卷
cat archive.zip.* > archive.zip

# 或使用 7z
7z x archive.zip.001
```

### 套路 8: 密码爆破（弱密码）

**特征**: 压缩包有密码，但密码较弱

**解法**:
```bash
# 快速爆破常见密码
fcrackzip -u -D -p common_passwords.txt archive.zip

# 暴力破解 4 位数字
fcrackzip -u -b -c '1' -l 4-4 archive.zip

# 暴力破解 6 位字母+数字
fcrackzip -u -b -c 'aA1' -l 6-6 archive.zip
```

**常见弱密码**:
- 纯数字: 123456, 000000, 123123
- 题目相关: ctf, flag, admin
- 键盘序列: qwerty, 123qwe

### 套路 9: 时间戳隐藏信息

**特征**: 文件的修改时间有规律

**解法**:
```python
import zipfile
from datetime import datetime

with zipfile.ZipFile('archive.zip') as zf:
    for info in zf.infolist():
        dt = datetime(*info.date_time)
        print(f"{info.filename}: {dt}")
        # 时间戳可能编码了信息
        # 例如: 小时+分钟+秒 = ASCII 码
```

### 套路 10: RAR 固实压缩

**特征**: RAR 使用固实压缩，无法单独提取文件

**解法**:
```bash
# 必须完整解压
rar x -kb archive.rar

# 或转换为非固实压缩
rar a -m0 new.rar @filelist.txt
```

## 实战技巧

### 技巧 1: 快速判断压缩包类型

```bash
#!/bin/bash
FILE=$1

# 文件类型
file $FILE

# 查看内容
case $FILE in
    *.zip)
        unzip -l $FILE
        unzip -z $FILE  # 注释
        ;;
    *.rar)
        rar l $FILE
        ;;
    *.7z)
        7z l $FILE
        ;;
    *.tar.gz|*.tgz)
        tar -tzf $FILE
        ;;
esac

# 检查加密
if unzip -l $FILE 2>&1 | grep -q "encrypted"; then
    echo "[!] Encrypted ZIP detected"
fi
```

### 技巧 2: 批量密码尝试

```python
#!/usr/bin/env python3
"""批量尝试常见密码"""
import zipfile

common_passwords = [
    '', '123456', 'password', 'admin', 'root',
    'ctf', 'flag', 'key', '000000', '123123',
    'qwerty', '123qwe', 'admin123', 'root123'
]

def try_passwords(zip_file, passwords):
    with zipfile.ZipFile(zip_file) as zf:
        for pwd in passwords:
            try:
                zf.extractall(pwd=pwd.encode())
                print(f"[+] Password found: {pwd}")
                return pwd
            except:
                pass
    print("[-] No password found")
    return None

if __name__ == '__main__':
    import sys
    try_passwords(sys.argv[1], common_passwords)
```

### 技巧 3: 压缩包信息提取

```python
#!/usr/bin/env python3
"""提取压缩包所有元数据"""
import zipfile
import json

def extract_metadata(zip_file):
    metadata = {
        'files': [],
        'comment': None,
        'encrypted': False
    }
    
    with zipfile.ZipFile(zip_file) as zf:
        # 全局注释
        if zf.comment:
            metadata['comment'] = zf.comment.decode('utf-8', errors='ignore')
        
        # 文件信息
        for info in zf.infolist():
            file_meta = {
                'filename': info.filename,
                'crc32': f"{info.CRC:08x}",
                'size': info.file_size,
                'compressed_size': info.compress_size,
                'date': f"{info.date_time}",
                'comment': info.comment.decode('utf-8', errors='ignore') if info.comment else None
            }
            
            # 检查加密
            if info.flag_bits & 0x1:
                file_meta['encrypted'] = True
                metadata['encrypted'] = True
            
            metadata['files'].append(file_meta)
    
    return metadata

if __name__ == '__main__':
    import sys
    meta = extract_metadata(sys.argv[1])
    print(json.dumps(meta, indent=2, ensure_ascii=False))
```

### 技巧 4: ZIP 文件修复

```python
#!/usr/bin/env python3
"""修复损坏的 ZIP 文件"""
import struct

def fix_zip_header(filename):
    """修复 ZIP 文件头"""
    with open(filename, 'rb') as f:
        data = bytearray(f.read())
    
    # 检查文件头
    if data[:4] != b'PK\x03\x04':
        print("[*] Fixing file header...")
        data[:4] = b'PK\x03\x04'
    
    # 保存修复后的文件
    with open(f"fixed_{filename}", 'wb') as f:
        f.write(data)
    
    print(f"[+] Saved to fixed_{filename}")

if __name__ == '__main__':
    import sys
    fix_zip_header(sys.argv[1])
```

## 无工具替代方案

当没有专业密码爆破工具时：

### Python 标准库 (zipfile)

```python
#!/usr/bin/env python3
"""纯 Python 压缩包分析"""

import zipfile
import struct

# 1. 查看压缩包信息 (替代 unzip -l)
def list_zip(filename):
    with zipfile.ZipFile(filename) as zf:
        for info in zf.infolist():
            print(f"File: {info.filename}")
            print(f"  Size: {info.file_size} bytes")
            print(f"  Compressed: {info.compress_size} bytes")
            print(f"  CRC32: {info.CRC:08x}")
            print(f"  Date: {info.date_time}")
            if info.flag_bits & 0x1:
                print("  [ENCRYPTED]")

# 2. 简单密码尝试 (替代 fcrackzip)
def try_passwords(filename, passwords):
    with zipfile.ZipFile(filename) as zf:
        for pwd in passwords:
            try:
                zf.extractall(pwd=pwd.encode())
                print(f"[+] Password found: {pwd}")
                return pwd
            except:
                pass
    print("[-] Password not found")
    return None

# 常见密码列表
common_passwords = [
    '', '123456', 'password', 'admin', 'root',
    'ctf', 'flag', 'key', '000000', '123123',
    'qwerty', '123qwe', 'admin123', '1234567890'
]

# 3. 伪加密检测与修复
def fix_fake_encrypt(filename):
    with open(filename, 'rb') as f:
        data = bytearray(f.read())
    
    # 查找并修复 Local File Header
    pos = 0
    fixed = False
    while True:
        pos = data.find(b'PK\x03\x04', pos)
        if pos == -1:
            break
        # General purpose bit flag at offset +6
        if data[pos + 6] & 0x01:
            data[pos + 6] &= 0xFE
            fixed = True
        pos += 4
    
    # 查找并修复 Central Directory
    pos = 0
    while True:
        pos = data.find(b'PK\x01\x02', pos)
        if pos == -1:
            break
        if data[pos + 8] & 0x01:
            data[pos + 8] &= 0xFE
            fixed = True
        pos += 4
    
    if fixed:
        with open('fixed_' + filename, 'wb') as f:
            f.write(data)
        print(f"[+] Fixed: fixed_{filename}")
    else:
        print("[-] No fake encryption detected")

# 4. CRC32 碰撞 (小文件爆破)
import binascii
import itertools
import string

def crack_crc32(target_crc, max_len=4, charset=string.ascii_letters + string.digits):
    for length in range(1, max_len + 1):
        print(f"[*] Trying length {length}...")
        for attempt in itertools.product(charset, repeat=length):
            data = ''.join(attempt).encode()
            if (binascii.crc32(data) & 0xffffffff) == target_crc:
                print(f"[+] Found: {data.decode()}")
                return data.decode()
    return None
```

### 在线工具替代

```yaml
密码爆破:
  - 暂无可靠在线爆破（安全原因）
  - 可用 Python 脚本替代

ZIP 分析:
  - https://www.online-utility.org/file/analyze.jsp
  - 本地 Python zipfile 模块

在线解压:
  - https://extract.me/ - 在线解压
  - https://www.ezyzip.com/ - 在线 ZIP 工具
```

### 系统自带命令

```bash
# 列出内容 (通常系统自带)
unzip -l archive.zip
tar -tzf archive.tar.gz

# 尝试解压
unzip archive.zip
tar -xzf archive.tar.gz

# 查看 ZIP 结构
zipinfo archive.zip

# 简单字符串搜索
strings archive.zip | grep -i password
strings archive.zip | grep -i flag

# 手工十六进制查看加密标志
xxd archive.zip | head -20
# 查看偏移 +6 位置的加密标志
```

### 纯手工修复伪加密

```bash
# 1. 用 xxd 查看
xxd archive.zip | head -5
# 找到 504b 0304 (Local File Header)
# 偏移 +6 位置如果是 09 00 表示加密

# 2. 用 sed 或 Python 修改
# 将加密标志位清零
python3 -c "
data = bytearray(open('archive.zip', 'rb').read())
data[6] = data[6] & 0xFE  # 清除加密位
open('fixed.zip', 'wb').write(data)
"
```

## 工具速查

```bash
# 查看内容
unzip -l archive.zip        # ZIP 列表
7z l archive.7z             # 7Z 列表
rar l archive.rar           # RAR 列表
tar -tzf archive.tar.gz     # TAR.GZ 列表

# 解压
unzip archive.zip           # ZIP
7z x archive.7z             # 7Z
rar x archive.rar           # RAR
tar -xzf archive.tar.gz     # TAR.GZ

# 密码爆破
fcrackzip -u -D -p wordlist.txt archive.zip
zip2john archive.zip > hash.txt && john hash.txt

# 明文攻击
bkcrack -C encrypted.zip -c file.txt -P plain.zip -p file.txt

# 伪加密修复
python3 scripts/zip_fake_encrypt.py archive.zip

# 结构分析
zipdetails archive.zip
```

## 脚本参考

详见 `scripts/zip_fake_encrypt.py`
