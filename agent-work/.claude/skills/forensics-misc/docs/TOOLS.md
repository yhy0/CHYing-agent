# 🔧 CTF Misc 工具安装指南

## 系统要求

- **操作系统**: Linux (推荐 Ubuntu/Kali) / macOS / Windows (WSL)
- **Python**: 3.8+
- **磁盘空间**: 至少 5GB（包含工具和依赖）

---

## 📦 核心工具安装

### 1. Python 环境

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-dev

# macOS
brew install python3

# Python 库
pip3 install pillow pycryptodome numpy scipy pyzbar
```

### 2. 文件分析工具

```bash
# Ubuntu/Debian
sudo apt install binwalk foremost exiftool file xxd

# macOS
brew install binwalk foremost exiftool

# Binwalk (最新版)
git clone https://github.com/ReFirmLabs/binwalk.git
cd binwalk
sudo python3 setup.py install
```

### 3. 压缩包工具

```bash
# Ubuntu/Debian
sudo apt install p7zip-full unzip unrar fcrackzip

# macOS
brew install p7zip unrar fcrackzip

# John the Ripper
sudo apt install john

# Hashcat (GPU 加速密码爆破)
sudo apt install hashcat

# bkcrack (ZIP 明文攻击)
wget https://github.com/kimci86/bkcrack/releases/latest/download/bkcrack-*-Linux.tar.gz
tar -xzf bkcrack-*-Linux.tar.gz
sudo cp bkcrack-*/bkcrack /usr/local/bin/
```

---

## 🖼️ 图片隐写工具

### zsteg (PNG/BMP LSB 分析)

```bash
# 需要 Ruby
sudo apt install ruby ruby-dev
sudo gem install zsteg
```

### stegsolve (图片通道分析)

```bash
# 下载 JAR 文件
wget http://www.caesum.com/handbook/Stegsolve.jar -O ~/stegsolve.jar

# 运行
java -jar ~/stegsolve.jar
```

### steghide / stegseek (JPG 隐写)

```bash
# steghide
sudo apt install steghide

# stegseek (steghide 密码爆破)
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_*_amd64.deb
sudo dpkg -i stegseek_*_amd64.deb
```

### pngcheck (PNG 结构检查)

```bash
sudo apt install pngcheck
```

---

## 🎵 音频分析工具

### Audacity (频谱图可视化)

```bash
# Ubuntu/Debian
sudo apt install audacity

# macOS
brew install --cask audacity
```

### sox (音频处理)

```bash
sudo apt install sox libsox-fmt-all
```

### ffmpeg (音视频处理)

```bash
sudo apt install ffmpeg
```

### multimon-ng (摩尔斯/DTMF 解码)

```bash
sudo apt install multimon-ng
```

---

## 📡 流量分析工具

### Wireshark / tshark

```bash
# Ubuntu/Debian
sudo apt install wireshark tshark

# 允许非 root 用户抓包
sudo usermod -aG wireshark $USER
# 重新登录生效

# macOS
brew install --cask wireshark
```

### NetworkMiner (文件提取)

```bash
# 下载 .NET 版本
wget https://www.netresec.com/?download=NetworkMiner -O NetworkMiner.zip
unzip NetworkMiner.zip
cd NetworkMiner_*/
mono NetworkMiner.exe
```

### scapy (Python 流量分析)

```bash
pip3 install scapy
```

---

## 🧠 内存取证工具

### Volatility 3 (推荐)

```bash
# 方法 1: pip 安装
pip3 install volatility3

# 方法 2: 源码安装
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
python3 setup.py install

# 验证安装
vol -h
```

### Volatility 2 (兼容性)

```bash
# 下载独立版本
wget https://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip
unzip volatility_2.6_lin64_standalone.zip
sudo mv volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone /usr/local/bin/vol2
sudo chmod +x /usr/local/bin/vol2
```

### MemProcFS

```bash
# 下载最新版本
wget https://github.com/ufrisk/MemProcFS/releases/latest/download/MemProcFS_*_linux_x64.tar.gz
tar -xzf MemProcFS_*_linux_x64.tar.gz
sudo mv memprocfs /usr/local/bin/
```

### bulk_extractor (批量提取)

```bash
sudo apt install bulk-extractor
```

---

## 🔠 编码/密码工具

### CyberChef (在线工具)

访问: https://gchq.github.io/CyberChef/

### dcode.fr (古典密码)

访问: https://www.dcode.fr/

### base58 (Python 库)

```bash
pip3 install base58
```

---

## 🛠️ 其他实用工具

### hexedit (十六进制编辑器)

```bash
sudo apt install hexedit
```

### qpdf (PDF 处理)

```bash
sudo apt install qpdf
```

### imagemagick (图片处理)

```bash
sudo apt install imagemagick
```

---

## 📋 验证安装

运行以下命令验证工具是否正确安装：

```bash
#!/bin/bash
echo "=== CTF Misc Tools Check ==="

# 文件分析
command -v file && echo "✓ file" || echo "✗ file"
command -v binwalk && echo "✓ binwalk" || echo "✗ binwalk"
command -v foremost && echo "✓ foremost" || echo "✗ foremost"
command -v exiftool && echo "✓ exiftool" || echo "✗ exiftool"

# 图片隐写
command -v zsteg && echo "✓ zsteg" || echo "✗ zsteg"
command -v steghide && echo "✓ steghide" || echo "✗ steghide"
command -v pngcheck && echo "✓ pngcheck" || echo "✗ pngcheck"

# 音频
command -v sox && echo "✓ sox" || echo "✗ sox"
command -v ffmpeg && echo "✓ ffmpeg" || echo "✗ ffmpeg"
command -v audacity && echo "✓ audacity" || echo "✗ audacity"

# 流量
command -v tshark && echo "✓ tshark" || echo "✗ tshark"
command -v wireshark && echo "✓ wireshark" || echo "✗ wireshark"

# 内存取证
command -v vol && echo "✓ volatility3" || echo "✗ volatility3"

# 压缩包
command -v 7z && echo "✓ 7z" || echo "✗ 7z"
command -v fcrackzip && echo "✓ fcrackzip" || echo "✗ fcrackzip"
command -v john && echo "✓ john" || echo "✗ john"

# Python 库
python3 -c "import PIL" && echo "✓ Pillow" || echo "✗ Pillow"
python3 -c "import Crypto" && echo "✓ pycryptodome" || echo "✗ pycryptodome"

echo "=== Check Complete ==="
```

---

## 🐳 Docker 一键环境（推荐）

```dockerfile
FROM ubuntu:22.04

RUN apt update && apt install -y \
    python3 python3-pip \
    binwalk foremost exiftool file xxd \
    p7zip-full unzip unrar fcrackzip john \
    wireshark tshark \
    sox ffmpeg audacity \
    ruby ruby-dev \
    && gem install zsteg \
    && pip3 install volatility3 pillow pycryptodome scapy

WORKDIR /ctf
CMD ["/bin/bash"]
```

构建并运行：

```bash
docker build -t ctf-misc .
docker run -it -v $(pwd):/ctf ctf-misc
```

---

## 📚 参考资源

- [Volatility 3 文档](https://volatility3.readthedocs.io/)
- [binwalk 文档](https://github.com/ReFirmLabs/binwalk/wiki)
- [Wireshark 用户指南](https://www.wireshark.org/docs/wsug_html_chunked/)
- [CTF Wiki](https://ctf-wiki.org/)

---

**最后更新**: 2025-12-24
