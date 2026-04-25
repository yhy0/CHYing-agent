---
name: forensics-misc
description: Use when facing digital forensics or misc challenges involving disk images, memory dumps, network captures, steganography, file format analysis, encoding puzzles, sandbox escapes, or archive manipulation
---

# CTF Forensics & Misc Solver

## Core Objective

你是专业的 CTF Forensics & Misc 解题助手。工程化逆向出题人思路：系统识别隐藏层 → 自动推理路径 → 生成可执行脚本 → 逐层剥离直到找到 flag。

**隐性线索**: 文件名、题目描述、出题人名字都可能是密码提示；文件时间戳可能隐藏信息。

---

## Phase 1: 通用初始侦察（对任何文件立即执行）

```bash
file <FILE>                                    # 文件类型
xxd <FILE> | head -20                          # 魔数
binwalk <FILE>                                 # 嵌套检测
strings <FILE> | grep -iE "flag\{|ctf|key|pass|secret" | head -20
exiftool <FILE> 2>/dev/null | head -40         # 元数据
```

---

## Phase 2: 类型识别 + 立即执行命令

根据 Phase 1 识别结果，找到匹配类型，**先执行下方命令，再读 module 深入分析**。

### 🖼 图片隐写 (.png / .jpg / .bmp / .gif / .webp)

**Module**: [steganography](modules/steganography.md) · [stego-image](modules/stego-image.md) · [stego-advanced](modules/stego-advanced.md)

```bash
# PNG — 立即执行
zsteg -a <FILE> 2>/dev/null | head -40
pngcheck -v <FILE>
python3 -c "from PIL import Image; img=Image.open('<FILE>'); print(f'Size:{img.size} Mode:{img.mode}')"
convert <FILE> -separate /tmp/channel_%d.png   # 通道分离

# JPEG — 立即执行
steghide info <FILE> -p "" 2>&1
steghide extract -sf <FILE> -p "" -f 2>/dev/null
exiftool <FILE> | grep -iE "comment|thumbnail|gps|author"
binwalk -e <FILE>

# BMP/GIF — 立即执行
zsteg -a <FILE> 2>/dev/null | head -40         # BMP also supported
python3 -c "
from PIL import Image
img = Image.open('<FILE>')
print(f'Size:{img.size} Mode:{img.mode} Frames:{getattr(img,\"n_frames\",1)}')
if hasattr(img,'n_frames') and img.n_frames > 1:
    for i in range(min(img.n_frames,50)):
        img.seek(i); img.save(f'/tmp/frame_{i:03d}.png')
    print(f'Extracted {min(img.n_frames,50)} frames to /tmp/frame_*.png')
"
```

**Magic bytes**: `89 50 4E 47` → PNG · `FF D8 FF` → JPEG · `42 4D` → BMP · `47 49 46 38` → GIF

### 🔊 音频隐写 (.wav / .mp3 / .flac / .ogg / .m4a)

**Module**: [stego-advanced](modules/stego-advanced.md) (Audio section)

```bash
# 频谱图 + DTMF + 字符串
sox <FILE> -n spectrogram -o /tmp/spec.png && echo "Spectrogram: /tmp/spec.png"
multimon-ng -t wav -a DTMF -a MORSE <FILE> 2>/dev/null | head -20
strings <FILE> | grep -iE "flag|ctf|key" | head -10
mediainfo <FILE>

# LSB 音频隐写检查
python3 -c "
import wave, struct
w = wave.open('<FILE>','rb')
frames = w.readframes(min(w.getnframes(), 8000))
samples = struct.unpack(f'{len(frames)//2}h', frames)
lsb = ''.join(str(s & 1) for s in samples[:800])
chars = [chr(int(lsb[i:i+8],2)) for i in range(0,len(lsb)-7,8) if 32<=int(lsb[i:i+8],2)<127]
print('LSB text:', ''.join(chars[:80]))
" 2>/dev/null

# DeepSound 检查
steghide info <FILE> -p "" 2>&1               # steghide also works on WAV
```

**Magic bytes**: `52 49 46 46` → WAV · `49 44 33` → MP3 (ID3) · `FF FB` → MP3 (no ID3)

### 📡 流量包 (.pcap / .pcapng / .cap)

**Module**: [network](modules/network.md) · [network-advanced](modules/network-advanced.md)

```bash
# 会话概览 + 协议分布
tshark -r <FILE> -q -z conv,tcp 2>/dev/null | head -25
tshark -r <FILE> -q -z io,phs 2>/dev/null | head -30

# HTTP 请求/数据
tshark -r <FILE> -Y "http.request" -T fields -e http.request.method -e http.host -e http.request.uri 2>/dev/null | head -30

# DNS 查询（常见隐蔽信道）
tshark -r <FILE> -Y "dns.qry.name" -T fields -e dns.qry.name 2>/dev/null | sort -u | head -30

# 导出 HTTP 对象
mkdir -p /tmp/http_objects && tshark -r <FILE> --export-objects http,/tmp/http_objects 2>/dev/null
ls /tmp/http_objects/ 2>/dev/null | head -20

# FTP/SMTP 数据
tshark -r <FILE> -Y "ftp-data or smtp" -T fields -e data 2>/dev/null | head -20

# 快速 flag 搜索
tshark -r <FILE> -Y "frame contains \"flag{\"" 2>/dev/null | head -5
```

**Magic bytes**: `D4 C3 B2 A1` / `A1 B2 C3 D4` → PCAP · `0A 0D 0D 0A` → PCAPNG

### 🧠 内存镜像 (.raw / .vmem / .dmp / .lime / .vmss)

**Module**: [disk-and-memory](modules/disk-and-memory.md)

```bash
# OS 检测（先 Windows 后 Linux）
vol3 -f <FILE> windows.info 2>/dev/null || vol3 -f <FILE> linux.bash 2>/dev/null || vol3 -f <FILE> banners.Banners 2>/dev/null

# 进程树
vol3 -f <FILE> windows.pstree 2>/dev/null || vol3 -f <FILE> linux.pslist 2>/dev/null

# 关键文件/字符串搜索
vol3 -f <FILE> windows.filescan 2>/dev/null | grep -iE "flag|secret|key|pass|desktop|document" | head -20

# 命令行历史
vol3 -f <FILE> windows.cmdline 2>/dev/null | head -30

# 网络连接
vol3 -f <FILE> windows.netscan 2>/dev/null | head -20
```

### 💾 磁盘镜像 (.dd / .img / .e01 / .ova / .vmdk / .dmg)

**Module**: [disk-and-memory](modules/disk-and-memory.md) · [disk-advanced](modules/disk-advanced.md) · [disk-recovery](modules/disk-recovery.md)

```bash
# 分区表
fdisk -l <FILE> 2>/dev/null || mmls <FILE> 2>/dev/null

# 文件列表
fls -r <FILE> 2>/dev/null | head -60

# 已删除文件
fls -r -d <FILE> 2>/dev/null | head -30

# 快速 flag 搜索
strings <FILE> | grep -iE "flag\{|ctf\{" | head -10

# 挂载检查
mkdir -p /tmp/mnt && mount -o loop,ro <FILE> /tmp/mnt 2>/dev/null && ls -la /tmp/mnt/ && umount /tmp/mnt 2>/dev/null
```

### 🪟 Windows 取证 (.evtx / SAM / SYSTEM / NTUSER.DAT)

**Module**: [windows](modules/windows.md)

```bash
# 注册表 hive 分析
python3 -c "
from Registry import Registry
reg = Registry.Registry('<FILE>')
def walk(key, depth=0):
    print('  '*depth + key.name())
    for v in key.values():
        print('  '*(depth+1) + f'{v.name()}: {v.value()}')
    for sk in key.subkeys():
        if depth < 2: walk(sk, depth+1)
walk(reg.root())
" 2>/dev/null | head -60

# evtx 解析
python3 -c "
import Evtx.Evtx as evtx
with evtx.Evtx('<FILE>') as log:
    for i, record in enumerate(log.records()):
        if i >= 30: break
        print(record.xml())
" 2>/dev/null | head -80

# 快速字符串
strings <FILE> | grep -iE "flag|password|admin|secret" | head -20
```

### 📦 压缩包 (.zip / .rar / .7z / .tar / .gz)

**Module**: [archive](modules/archive.md)

```bash
# 文件信息 + 内容列表
file <FILE>
7z l <FILE> 2>/dev/null || unzip -l <FILE> 2>/dev/null

# ZIP 详细信息（CRC、大小、加密方式）
python3 -c "
import zipfile
try:
    z = zipfile.ZipFile('<FILE>')
    for i in z.infolist():
        enc = 'ENCRYPTED' if i.flag_bits & 0x1 else 'plain'
        print(f'{i.filename}  CRC:{i.CRC:08x}  Size:{i.file_size}  Compressed:{i.compress_size}  {enc}')
except Exception as e: print(e)
" 2>/dev/null

# ZIP 伪加密检测
python3 -c "
data = open('<FILE>','rb').read()
import struct
pos = 0
while True:
    pos = data.find(b'PK\x01\x02', pos)
    if pos < 0: break
    flag = struct.unpack('<H', data[pos+8:pos+10])[0]
    if flag & 1: print(f'Central dir @{pos}: flag={flag:#x} — may be fake encryption')
    pos += 4
" 2>/dev/null

# 尝试空密码解压
7z x <FILE> -o/tmp/extracted -p"" -y 2>/dev/null && echo "Extracted with empty password" && ls /tmp/extracted/
```

### 🔤 编码/文本谜题

**Module**: [encoding](modules/encoding.md)

```bash
# 自动多层 base64 解码
python3 -c "
import base64, sys
data = open('<FILE>','rb').read().strip()
for i in range(10):
    try:
        decoded = base64.b64decode(data)
        print(f'Layer {i+1} (base64): {decoded[:120]}')
        data = decoded
    except: break
print(f'Final: {data[:200]}')
" 2>/dev/null

# 常见编码检测
python3 -c "
import re, sys
data = open('<FILE>','r',errors='ignore').read().strip()
if re.match(r'^[01\s]+$', data): print('Binary detected')
elif re.match(r'^[0-9a-fA-F\s]+$', data): print('Hex detected:', bytes.fromhex(data.replace(' ',''))[:100])
elif re.match(r'^[A-Za-z0-9+/=\s]+$', data): print('Possibly Base64')
elif re.match(r'^[.-/ ]+$', data): print('Morse code detected')
elif '\\\\u' in data or '&#' in data: print('Unicode/HTML entities detected')
else: print('Unknown encoding, first 200 chars:', data[:200])
" 2>/dev/null
```

### 🐍 Python 沙箱逃逸 (pyjail)

**Module**: [pyjails](modules/pyjails.md)

**题目特征**: 交互式 Python shell，禁用了 import/exec/eval/os 等

```python
# 快速测试 payloads（依次尝试）
__import__('os').system('cat /flag*')
breakpoint()                                   # pdb shell → import os
().__class__.__bases__[0].__subclasses__()      # 列出所有子类
getattr(__builtins__, '__import__')('os').system('cat /flag*')
eval(bytes([105,109,112,111,114,116,32,111,115]).decode())  # "import os"
[x for x in ().__class__.__bases__[0].__subclasses__() if 'warning' in str(x).lower()][0]()._module.__builtins__['__import__']('os').system('cat /flag*')
```

### 🐚 Bash 沙箱逃逸 (bashjail)

**Module**: [bashjails](modules/bashjails.md)

**题目特征**: 受限 shell，禁用了常见命令

```bash
# 快速逃逸尝试
$0                          # 通常是 /bin/sh 或 /bin/bash
${PATH:0:1}                 # 产生 /
cat${IFS}/flag*             # IFS 绕过空格限制
/???/??t /???g*             # glob 绕过: /bin/cat /flag*
$(printf '\x63\x61\x74') /flag*   # printf 绕过: cat
echo $HISTFILE              # 可能可以读取文件
exec 3< /flag && cat <&3   # fd 重定向读文件
```

### 📻 硬件/信号 (.sal / .sub / .bin)

**Module**: [signals-and-hardware](modules/signals-and-hardware.md)

```bash
# Saleae 逻辑分析仪
python3 -c "
import csv, sys
with open('<FILE>') as f:
    reader = csv.reader(f)
    for i, row in enumerate(reader):
        if i >= 30: break
        print(row)
" 2>/dev/null

# Flipper Zero SubGHz
strings <FILE> | head -40
file <FILE>
xxd <FILE> | head -30
```

### 🖨 3D 打印 (.g / .bgcode / .gcode)

**Module**: [3d-printing](modules/3d-printing.md)

```bash
# G-code 分析
head -50 <FILE>
grep -E "^G[01] " <FILE> | head -30           # 移动指令
python3 -c "
lines = open('<FILE>').readlines()
coords = []
for l in lines:
    if l.startswith('G1') or l.startswith('G0'):
        parts = {p[0]:float(p[1:]) for p in l.split() if p[0] in 'XYZ'}
        if 'X' in parts and 'Y' in parts: coords.append((parts['X'],parts['Y']))
print(f'Total move commands: {len(coords)}')
if coords: print(f'X range: {min(c[0] for c in coords):.1f}-{max(c[0] for c in coords):.1f}')
if coords: print(f'Y range: {min(c[1] for c in coords):.1f}-{max(c[1] for c in coords):.1f}')
" 2>/dev/null
```

---

## Module Dispatch Table

| Module | 覆盖范围 |
|--------|---------|
| [disk-and-memory](modules/disk-and-memory.md) | Volatility 3, disk mounting/carving, VM/OVA/VMDK, VMware snapshots, coredumps, KAPE, ransomware, Android/Docker/cloud, BSON, TrueCrypt/VeraCrypt |
| [disk-advanced](modules/disk-advanced.md) | Deleted partitions, ZFS, GPT GUID encoding, VMDK sparse, memory carving, ransomware key recovery, APFS snapshots, RAID 5 XOR |
| [disk-recovery](modules/disk-recovery.md) | LUKS master key, PRNG brute-force, VBA recovery, XFS reconstruction, tar duplicate, matryoshka FS, anti-carving, BTRFS/FAT16/ext2 |
| [windows](modules/windows.md) | Registry, SAM, event logs, recycle bin, NTFS ADS, USN journal, PowerShell history, Defender MPLog, WMI, Amcache |
| [linux-forensics](modules/linux-forensics.md) | Log analysis, Docker forensics, browser credentials, Git recovery, KeePass, browser artifacts, VBA macro, Ethereum |
| [network](modules/network.md) | tcpdump, TLS/SSL decryption, Wireshark, SMB3, 5G/NR, USB HID steno, BCD, HTTP exfil, WiFi decrypt, PCAP repair |
| [network-advanced](modules/network-advanced.md) | Packet timing, USB HID mouse, NTLMv2 crack, TCP flag covert channel, DNS stego, multi-layer PCAP XOR, Brotli bomb, SMB RID, Timeroasting |
| [steganography](modules/steganography.md) | Binary border stego, PDF multi-layer, SVG keyframes, PNG reorder, file overlays, GIF Morse, GZSteg, Kitty graphics, ANSI escape, autostereograms |
| [stego-image](modules/stego-image.md) | JPEG DQT LSB, BMP bitplane QR, image puzzle reassembly, F5 DCT, PNG palette stego, QR reconstruction, pixel permutation, JPEG slack, RGB parity |
| [stego-advanced](modules/stego-advanced.md) | FFT frequency, DTMF, SSTV+LSB, multi-track subtraction, cross-channel LSB, audio FFT notes, spectrogram QR, video frame accumulation, DeepSound, silence analysis |
| [signals-and-hardware](modules/signals-and-hardware.md) | VGA/HDMI TMDS/DisplayPort, Voyager Golden Record, side-channel DPA, Saleae UART, Flipper Zero, keyboard acoustic, CD audio, I2C, punched card |
| [3d-printing](modules/3d-printing.md) | PrusaSlicer binary G-code, QOIF, G-code visualization |
| [archive](modules/archive.md) | ZIP 伪加密, CRC32 碰撞, 明文攻击 (bkcrack), 密码爆破, 递归套娃, 损坏修复, 分卷合并, 时间戳分析 |
| [encoding](modules/encoding.md) | Base64/32/58/85, Hex/Binary/Octal, ROT/Caesar, 摩尔斯/培根/栅栏, URL/HTML, 递归多层解码 |
| [pyjails](modules/pyjails.md) | Python 沙箱逃逸: func_globals 链, 受限字符集, 类持久化, builtins 重建, eval/exec 绕过, decorator escape |
| [bashjails](modules/bashjails.md) | Bash 沙箱逃逸: HISTFILE, 命令注入, 特殊字符绕过, 受限 shell 逃逸, $0 expansion |

---

## Available Tools

| 工具 | 命令 | 用途 |
|------|------|------|
| file | `file target` | 文件类型识别 |
| binwalk | `binwalk -e file` | 嵌套文件提取 |
| foremost | `foremost -i file -o out/` | 文件雕刻/恢复 |
| steghide | `steghide extract -sf img.jpg` | JPG/WAV 隐写提取 |
| zsteg | `zsteg -a img.png` | PNG/BMP LSB 分析 |
| pngcheck | `pngcheck -v img.png` | PNG 结构/CRC 检查 |
| exiftool | `exiftool file` | 元数据查看 |
| strings | `strings -n 6 file` | 字符串提取 |
| xxd | `xxd file \| head -50` | 十六进制查看 |
| tshark | `tshark -r file.pcap -Y "http"` | 流量包分析 |
| sox | `sox in.wav -n spectrogram -o spec.png` | 音频频谱图 |
| ffmpeg | `ffmpeg -i input output` | 音视频转换 |
| john | `john --wordlist=dict hash.txt` | 密码破解 |
| fcrackzip | `fcrackzip -u -D -p dict f.zip` | ZIP 密码破解 |
| bkcrack | `bkcrack -C enc.zip -c f -P p.zip -p f` | ZIP 明文攻击 |
| volatility3 | `vol3 -f mem.dmp windows.info` | 内存取证 |
| sleuthkit | `fls -r image.dd` | 磁盘取证 |
| testdisk | `testdisk image.img` | 分区恢复 |
| pcapfix | `pcapfix -d corrupted.pcap` | PCAP 修复 |
| qpdf | `qpdf --decrypt in.pdf out.pdf` | PDF 解密 |
| imagemagick | `convert img.png -separate ch/` | 图像通道分离 |
| multimon-ng | `multimon-ng -t wav -a DTMF f.wav` | DTMF/摩尔斯解码 |

**Python 库**: `PIL/Pillow`, `pyzbar`, `scipy.fft`, `numpy`, `scapy`, `volatility3`, `pycryptodome`, `wave`, `struct`

---

## 扩展参考

沙箱逃逸模块来自 [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills)（MIT）：[pyjails](modules/pyjails.md) · [bashjails](modules/bashjails.md)
