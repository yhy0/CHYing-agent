---
category: misc
tags: [steganography, stego, lsb, zsteg, steghide, binwalk, exiftool, spectrogram, dtmf, png, jpeg, audio, pdf, 隐写术, 隐写, 图片隐写, 音频隐写]
triggers: [steganography, stego, hidden data, lsb, least significant bit, hidden in image, hidden in audio, spectrogram, exif, metadata, binwalk, embedded file, 隐写, 隐藏信息, 图片隐写]
related: [pcap_analysis, memory_forensics]
---

# 隐写术 (Steganography)

## 什么时候用

题目给了图片/音频/PDF 文件，flag 不在明文中，需要从文件的隐藏层提取数据。CTF misc 最经典的题型。

## 前提条件

- **有可疑文件**：PNG/JPEG/BMP/WAV/MP3/PDF 等
- **基础工具链**：`file`、`strings`、`binwalk`、`exiftool`、`xxd` 做初始分诊
- **专用工具**：根据文件类型选用 zsteg/steghide/stegsolve/sox 等

## 攻击步骤

### 1. 通用初始分诊（任何文件类型）

```bash
file challenge.*                                              # 文件类型
strings -a challenge.png | grep -iE "flag|ctf\{|key"         # 字符串搜索
exiftool challenge.png                                        # EXIF 元数据
binwalk -e challenge.png                                      # 嵌入文件提取
xxd challenge.png | tail -20                                  # 尾部附加数据
```

### 2. PNG 隐写

| 工具 | 用途 | 命令 |
|------|------|------|
| `zsteg` | PNG/BMP LSB 全自动 | `zsteg -a challenge.png` |
| `pngcheck` | 结构完整性校验 | `pngcheck -v challenge.png` |
| `stegsolve` | 可视化 bitplane | GUI 逐层翻看 |

**PNG 高度/CRC 修复：**
```python
import struct, zlib
with open('challenge.png', 'rb') as f:
    data = bytearray(f.read())
ihdr_start = 12
ihdr_data = data[ihdr_start:ihdr_start + 17]
stored_crc = struct.unpack('>I', data[ihdr_start + 17:ihdr_start + 21])[0]
for h in range(1, 4096):
    test = ihdr_data[:8] + struct.pack('>I', h) + ihdr_data[12:]
    if zlib.crc32(test) & 0xffffffff == stored_crc:
        print(f"正确高度: {h}")
        data[ihdr_start + 8:ihdr_start + 12] = struct.pack('>I', h)
        open('fixed.png', 'wb').write(data)
        break
```

**调色板隐写（未使用 palette entry 藏数据）：**
```python
from PIL import Image
img = Image.open('challenge.png')
palette, used = img.getpalette(), set(img.getdata())
flag = ''.join(chr(palette[i*3]) for i in range(256)
               if i not in used and 32 <= palette[i*3] <= 126)
```

### 3. JPEG 隐写

```bash
steghide extract -sf challenge.jpg -p ""       # 空密码先试
stegseek challenge.jpg rockyou.txt             # 密码暴破（极快）
exiftool -b -ThumbnailImage challenge.jpg > thumb.jpg  # 缩略图可能不同
```

### 4. 自定义 LSB 提取（标准工具无结果时）

```python
from PIL import Image; import re
img = Image.open('challenge.png')
bits = []
for y in range(img.height):
    for x in range(img.width):
        r, g, b = img.getpixel((x, y))[:3]
        bits.extend([r & 1, g & 1, b & 1])
        # 跨通道变体：bits.extend([(r>>0)&1, (g>>1)&1, (b>>2)&1])
data = bytearray(int(''.join(str(b) for b in bits[i:i+8]),2) for i in range(0,len(bits)-7,8))
match = re.search(rb'flag\{[^}]+\}', data, re.I)
if match: print(match.group().decode())
```

### 5. 音频隐写

```bash
sox audio.wav -n spectrogram -o spec.png -x 2000 -y 500 -z 80   # 频谱图（最常用）
sox audio.wav -t raw -r 22050 -e signed-integer -b 16 -c 1 - | multimon-ng -t raw -a DTMF -  # DTMF
stegolsb wavsteg -r -i audio.wav -o out.bin -n 1 -b 1000        # 音频 LSB
sox audio.wav reversed.wav reverse                                # 反转
ffprobe -hide_banner challenge.mkv                                # 多轨道检查
# 双轨差分
sox -m track0.wav "|sox track1.wav -p vol -1" diff.wav
sox diff.wav -n spectrogram -o diff_spec.png -X 2000 -Y 1000 -z 100 -h
```

**WAV LSB（纯 Python）：**
```python
import wave, struct
with wave.open('audio.wav','rb') as wav:
    frames = wav.readframes(wav.getnframes())
samples = struct.unpack(f'{len(frames)//2}h', frames)
bits = ''.join(str(s & 1) for s in samples)
text = ''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits)-7,8) if 32<=int(bits[i:i+8],2)<127)
print(text[:500])
```

### 6. PDF 隐写

```bash
strings -a file.pdf | grep -o 'flag{[^}]*}'   # 直接搜
exiftool file.pdf                               # 元数据字段
pdfimages -all file.pdf img                     # 提取图片 → 再 zsteg
mutool clean -d -c file.pdf clean.pdf && strings clean.pdf | grep flag
```

**PDF 排查清单**：`strings` → `exiftool` → `pdfimages` + `zsteg` → 编辑器查遮盖层 → `mutool` 解压流 → 检查 `%%EOF` 后附加数据。

### CTF 常见模式速查

| 模式 | 方法 |
|------|------|
| flag 在 LSB | `zsteg` / `stegsolve` / PIL 脚本 |
| flag 在频谱图 | `sox spectrogram` / Audacity |
| flag 在 EXIF | `exiftool` |
| 文件内嵌文件 | `binwalk -e` |
| PNG 高度截断 | CRC 暴力枚举高度 |
| JPEG 需密码 | `stegseek` 暴破 |
| DTMF 按键音 | `multimon-ng` |
| 视频多轨道 | `ffprobe` + `ffmpeg -map` |

## 常见坑

- **zsteg 只支持 PNG/BMP**：JPEG 有损压缩破坏 LSB，用 `steghide` 或 F5。对 JPEG 跑 zsteg 无效。
- **steghide 要密码**：先试空密码 `-p ""`，再 `stegseek` 跑字典。常见弱密码：`password`、题目名本身。
- **标准工具全无**：考虑非标准 bit 组合（R[0]G[1]B[2]）、像素过滤（近黑像素才携带数据）、调色板隐写、FFT 频域。
- **PNG APNG 陷阱**：普通 PNG 可能是 APNG（含隐藏帧）。`apngdis` 提取所有帧。
- **音频要看频谱不要听**：CTF 音频大多数答案在频谱图上。先出频谱图。
- **JPEG 缩略图**：`exiftool -b -ThumbnailImage` 提取，可能是修改前原图。
- **PDF 多层编码**：一个 PDF 可能同时有 metadata + URI + 图片 LSB + FlateDecode 流多个 flag。

## 变体

### FFT 频域隐写
```python
import numpy as np; from PIL import Image
img = np.array(Image.open('challenge.png')).astype(float)
mag = np.log(1 + np.abs(np.fft.fftshift(np.fft.fft2(img))))
Image.fromarray((mag/mag.max()*255).astype(np.uint8)).save('fft.png')
```

### 自动立体图（Magic Eye）
```python
import numpy as np; from PIL import Image
img = np.array(Image.open('stereogram.png'))
shift = 100  # 试 80-120
diff = np.abs(img[:,shift:].astype(int) - img[:,:-shift].astype(int))
Image.fromarray(diff.astype(np.uint8)).save('revealed.png')
```

### 视频帧累积
```bash
ffmpeg -i challenge.mp4 -vsync 0 frames/frame_%04d.png
```
```python
import numpy as np; from PIL import Image; import glob
frames = sorted(glob.glob('frames/*.png'))
acc = np.zeros(np.array(Image.open(frames[0])).shape, dtype=np.float64)
for f in frames: acc = np.maximum(acc, np.array(Image.open(f), dtype=np.float64))
Image.fromarray(acc.astype(np.uint8)).save('accumulated.png')
```

## 相关技术

- [[pcap_analysis]] — 从流量中提取的文件可能需要隐写分析
- [[memory_forensics]] — 内存中 dump 出的图片/文件可能包含隐写数据
