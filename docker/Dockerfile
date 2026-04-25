# Dockerfile for Kali Linux Security Tools Environment
# Kali Rolling base with comprehensive pentesting tools
# Supports: Web, Misc, PWN, Crypto, Red Team
#
# 多阶段构建：
#   docker build --target kali-tools   → 纯安全工具镜像（原有）
#   docker build --target chying-full  → 完整 CHYing-agent 镜像（含 Chrome + VNC）
#
# Builder stages (编译工具链仅在 builder 阶段存在，不进入最终镜像):
#   ghidra-builder: Maven + JDK 编译 GhidraMCP，完成后仅 COPY 产物

# ===================================================================
# Builder Stage: Ghidra + GhidraMCP 编译 (maven 仅在此阶段使用)
# ===================================================================
FROM maven:3-eclipse-temurin-21 AS ghidra-builder

ARG GHIDRA_VERSION=12.0.3
ARG GHIDRA_DATE=20260210
ARG GHIDRA_MCP_VERSION=v5.2.0

RUN apt-get update && apt-get install -y --no-install-recommends wget unzip git \
    && rm -rf /var/lib/apt/lists/*

# 下载 Ghidra
RUN wget -q -O /tmp/ghidra.zip \
        "https://xget-cfw.fireline.fun/gh/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    && unzip -q /tmp/ghidra.zip -d /opt/tools/ \
    && ln -sf "/opt/tools/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/tools/ghidra \
    && rm -f /tmp/ghidra.zip

# 克隆 ghidra-mcp
RUN git clone --depth 1 --branch "${GHIDRA_MCP_VERSION}" \
        https://xget-cfw.fireline.fun/gh/bethington/ghidra-mcp.git /opt/tools/ghidra-mcp \
    && rm -rf /opt/tools/ghidra-mcp/.git

# 将本地修复过的 bridge 文件覆盖上游版本
COPY docker/ghidra-mcp/bridge_mcp_ghidra.py /opt/tools/ghidra-mcp/bridge_mcp_ghidra.py

# Maven 国内镜像：public 聚合仓比仅 central 更全，降低依赖解析失败概率
ENV MAVEN_OPTS="-Dmaven.wagon.http.retryHandler.count=5"
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml << 'EOF'
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 https://maven.apache.org/xsd/settings-1.2.0.xsd">
  <mirrors>
    <mirror>
      <id>aliyun-public</id>
      <mirrorOf>central</mirrorOf>
      <name>Aliyun Maven public</name>
      <url>https://maven.aliyun.com/repository/public</url>
    </mirror>
  </mirrors>
</settings>
EOF

# 安装 Ghidra JARs 到 Maven 本地仓库并构建 Headless JAR
# 注意：ghidra-mcp 新版 pom 含 test 依赖 ghidra:DB（中央仓不存在）。仅 -DskipTests 仍会 test-compile 并解析失败；
# 使用 -Dmaven.test.skip=true 跳过测试编译，只打 headless 产物。
RUN set -eux; \
    GH=/opt/tools/ghidra; \
    V=${GHIDRA_VERSION}; \
    for art in \
        "Framework/Generic/lib/Generic:Generic" \
        "Framework/SoftwareModeling/lib/SoftwareModeling:SoftwareModeling" \
        "Framework/Project/lib/Project:Project" \
        "Framework/Docking/lib/Docking:Docking" \
        "Framework/Utility/lib/Utility:Utility" \
        "Framework/Gui/lib/Gui:Gui" \
        "Framework/FileSystem/lib/FileSystem:FileSystem" \
        "Framework/Help/lib/Help:Help" \
        "Framework/DB/lib/DB:DB" \
        "Features/Base/lib/Base:Base" \
        "Features/Decompiler/lib/Decompiler:Decompiler"; do \
        path="${art%%:*}"; name="${art##*:}"; \
        mvn -q install:install-file \
            -Dfile="${GH}/Ghidra/${path}.jar" \
            -DgroupId=ghidra -DartifactId="${name}" \
            -Dversion="${V}" -Dpackaging=jar; \
    done; \
    cd /opt/tools/ghidra-mcp && \
    mvn clean package -P headless -DskipTests -Dmaven.test.skip=true -q && \
    cp target/GhidraMCP-*.jar /opt/tools/ghidra-mcp/GhidraMCP.jar && \
    rm -rf /opt/tools/ghidra-mcp/target /root/.m2

# ===================================================================
# Main Stage: kali-tools
# ===================================================================
FROM kalilinux/kali-rolling AS kali-tools

ENV DEBIAN_FRONTEND=noninteractive

# ============================================================
# Phase 1a: Mirror Setup + Base System
# ============================================================
RUN set -eux; \
    mirrors="mirrors.aliyun.com/kali mirrors.cloud.tencent.com/kali mirrors.tencent.com/kali ftp.acc.umu.se/mirror/kali.org/kali mirror.math.princeton.edu/pub/kali"; \
    success=0; \
    for mirror in $mirrors; do \
        echo "deb http://$mirror kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list; \
        if apt-get update; then \
            echo "Using Kali mirror: $mirror"; \
            success=1; \
            break; \
        fi; \
    done; \
    if [ "$success" -ne 1 ]; then \
        echo "ERROR: apt-get update failed for all configured mirrors" >&2; \
        exit 1; \
    fi; \
    apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip python-is-python3 python3-dev \
    openjdk-21-jdk \
    build-essential gcc g++ make cmake \
    libgmp-dev libmpfr-dev libmpc-dev \
    curl git perl gnupg2 wget sudo jq unzip tree file xxd \
    libnet-ssleay-perl libio-socket-ssl-perl libcrypt-ssleay-perl libssl-dev ca-certificates \
    iputils-ping dnsutils iproute2 net-tools traceroute \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# ============================================================
# Phase 1b: Security Tools + Web Fuzzing + Toolchains
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # --- Core Security & Network ---
    nmap sqlmap netcat-traditional tcpdump \
    whatweb nuclei \
    smbclient smbmap python3-impacket \
    socat proxychains4 sslscan seclists \
    hydra hashid \
    libimage-exiftool-perl cewl \
    # --- Web Recon & Fuzzing ---
    subfinder \
    ffuf arjun wpscan \
    commix \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Web-Fuzzing-Box: high-quality Chinese-scene fuzzing dictionaries
RUN git clone --depth=1 https://xget-cfw.fireline.fun/gh/gh0stkey/Web-Fuzzing-Box.git /usr/share/wordlists/Web-Fuzzing-Box || true \
    && rm -rf /usr/share/wordlists/Web-Fuzzing-Box/.git

# ============================================================
# Phase 2: CTF Tools (Forensics + PWN + Red Team)
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # === File Analysis ===
    binwalk \
    foremost \
    sleuthkit \
    # === Archive Tools ===
    p7zip-full \
    unrar \
    fcrackzip \
    # === Image Steganography ===
    steghide \
    pngcheck \
    imagemagick \
    # === Audio/Video ===
    sox \
    libsox-fmt-all \
    ffmpeg \
    # === Network Forensics ===
    tshark \
    # === Password Cracking ===
    john \
    hashcat \
    # === Hex Editors ===
    hexedit \
    # === Ruby for zsteg ===
    ruby \
    ruby-dev \
    # === PDF Tools ===
    qpdf \
    poppler-utils \
    # === Additional Forensics ===
    bulk-extractor \
    # === Debuggers & Binary Analysis (PWN) ===
    gdb \
    gdb-multiarch \
    radare2 \
    # === Red Team / Lateral Movement ===
    crackmapexec \
    evil-winrm \
    chisel \
    impacket-scripts \
    # === C2 / Exploitation Framework ===
    metasploit-framework \
    postgresql \
    # === Terminal Multiplexer (交互式 shell 管理) ===
    tmux \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Install zsteg (Ruby gem for PNG/BMP LSB analysis)
RUN gem install zsteg || true

# ============================================================
# Phase 2b: Ghidra + GhidraMCP (从 builder 阶段复制，无需 Maven)
# ============================================================
COPY --from=ghidra-builder /opt/tools/ghidra /opt/tools/ghidra
COPY --from=ghidra-builder /opt/tools/ghidra-mcp /opt/tools/ghidra-mcp
# 安装 Python bridge 依赖
RUN pip3 install --break-system-packages --ignore-installed \
    "mcp>=1.5.0,<2.0.0" \
    "requests>=2.28.0,<3.0.0" \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/
ENV GHIDRA_HOME="/opt/tools/ghidra"

# ============================================================
# Phase 3: Environment Setup
# ============================================================
RUN mkdir -p /opt/tools

# Java environment (Ghidra 需要 JDK 21+，JAVA_HOME 必须指向含 bin/java 和 release 的目录)
# 通配符在 RUN 层展开，确保符号链接指向实际架构目录
RUN ln -sf $(ls -d /usr/lib/jvm/java-21-openjdk-* | head -1) /usr/lib/jvm/java-21
ENV JAVA_HOME="/usr/lib/jvm/java-21"

# ============================================================
# Phase 6: Python Security Packages
# ============================================================
# Fix binwalk/capstone ABI/API mismatch:
# binwalk 2.4.3 expects capstone.CS_ARCH_ARM64, which is removed/renamed in capstone 6.x.
# Pin to capstone 5.x to keep binwalk usable.
RUN pip3 install --break-system-packages --force-reinstall "capstone==5.0.3" \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/

# 注意：chardet 是 Debian 系统包，无法通过 pip 卸载
# 使用 --ignore-installed 跳过已安装的系统包冲突
RUN pip3 install --break-system-packages --ignore-installed chardet \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/ || true

RUN pip3 install --break-system-packages --ignore-installed \
    # === Web Security ===
    requests \
    aiohttp \
    jinja2 \
    'httpx[cli]' \
    ratelimit \
    beautifulsoup4 \
    websockets \
    clairvoyance \
    lxml \
    # === Crypto ===
    pycryptodomex \
    pycryptodome \
    gmpy2 \
    sympy \
    z3-solver \
    factordb-pycli \
    # === PWN ===
    pwntools \
    ropper \
    # === Forensics ===
    volatility3 \
    scapy \
    pillow \
    pyzbar \
    numpy \
    scipy \
    # === JWT ===
    pyjwt \
    # === Encoding ===
    base58 \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/

# 编译工具链已完成使命，卸载释放空间（保留 make，部分运行时工具需要）
RUN apt-get purge -y --auto-remove \
    build-essential gcc g++ cmake python3-dev \
    libgmp-dev libmpfr-dev libmpc-dev libssl-dev ruby-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# ============================================================
# Phase 7: Git-based Tools (使用 Xget 加速)
# ============================================================

# JWT Tool
RUN git clone --depth=1 https://xget-cfw.fireline.fun/gh/ticarpi/jwt_tool.git /opt/tools/jwt_tool || true && \
    rm -rf /opt/tools/jwt_tool/.git && \
    if [ -f /opt/tools/jwt_tool/jwt_tool.py ]; then chmod +x /opt/tools/jwt_tool/jwt_tool.py; fi

# tplmap - SSTI scanner
RUN git clone --depth=1 https://xget-cfw.fireline.fun/gh/epinna/tplmap.git /opt/tools/tplmap || true && \
    rm -rf /opt/tools/tplmap/.git && \
    if [ -f /opt/tools/tplmap/tplmap.py ]; then chmod +x /opt/tools/tplmap/tplmap.py; fi

# XSStrike - XSS scanner
RUN git clone --depth=1 https://xget-cfw.fireline.fun/gh/s0md3v/XSStrike.git /opt/tools/XSStrike || true && \
    rm -rf /opt/tools/XSStrike/.git && \
    if [ -d /opt/tools/XSStrike ]; then \
      cd /opt/tools/XSStrike && \
      pip3 install --break-system-packages -r requirements.txt || true; \
    fi

# Gopherus - SSRF exploitation
RUN git clone --depth=1 https://xget-cfw.fireline.fun/gh/tarunkant/Gopherus.git /opt/tools/Gopherus || true && \
    rm -rf /opt/tools/Gopherus/.git && \
    if [ -f /opt/tools/Gopherus/gopherus.py ]; then chmod +x /opt/tools/Gopherus/gopherus.py; fi

# phpggc - PHP deserialization chains
RUN git clone --depth=1 https://xget-cfw.fireline.fun/gh/ambionics/phpggc.git /opt/tools/phpggc || true && \
    rm -rf /opt/tools/phpggc/.git && \
    if [ -f /opt/tools/phpggc/phpggc ]; then chmod +x /opt/tools/phpggc/phpggc; fi

# RsaCtfTool - RSA attacks
RUN git clone --depth=1 hhttps://xget-cfw.fireline.fun/gh/RsaCtfTool/RsaCtfTool.git /opt/tools/RsaCtfTool || true && \
    rm -rf /opt/tools/RsaCtfTool/.git && \
    if [ -d /opt/tools/RsaCtfTool ]; then \
      cd /opt/tools/RsaCtfTool && \
      pip3 install --break-system-packages -r requirements.txt || true; \
    fi

# pwndbg - GDB plugin for PWN
RUN git clone --depth=1 https://xget-cfw.fireline.fun/gh/pwndbg/pwndbg.git /opt/tools/pwndbg || true && \
    if [ -d /opt/tools/pwndbg ]; then \
      cd /opt/tools/pwndbg && \
      ./setup.sh || true; \
    fi

# nuclei-templates - CVE/漏洞扫描模板（apt 装的 nuclei 不含模板）
RUN git clone --depth=1 https://xget-cfw.fireline.fun/gh/projectdiscovery/nuclei-templates.git \
        /root/.local/nuclei-templates || true \
    && rm -rf /root/.local/nuclei-templates/.git

# vulhub - CVE PoC 参考库（只保留 README 和 PoC 脚本，约 4MB）
RUN git clone --depth=1 https://xget-cfw.fireline.fun/gh/vulhub/vulhub.git /opt/tools/vulhub || true \
    && cd /opt/tools/vulhub \
    && find . -type f \( -name "docker-compose.*" -o -name "Dockerfile" -o -name "*.sh" \
        -o -name "*.sql" -o -name "*.conf" -o -name "*.xml" -o -name "*.yml" \
        -o -name "*.yaml" -o -name "*.jar" -o -name "*.war" -o -name "*.tar" \
        -o -name "*.gz" -o -name "*.zip" -o -name "*.key" -o -name "*.pem" \
        -o -name "*.crt" -o -name "*.properties" -o -name "*.ini" -o -name "*.cfg" \
        -o -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" -o -name "*.gif" \
        -o -name "*.svg" -o -name "*.ico" -o -name "*.pdf" -o -name "*.lock" \
        -o -name ".gitignore" -o -name ".dockerignore" -o -name "*.css" \
        -o -name "LICENSE*" -o -name "Makefile" \) -delete 2>/dev/null; \
    find . -type d -empty -delete 2>/dev/null; \
    rm -rf .git

# one_gadget - Find one-shot RCE gadgets in libc
RUN gem install one_gadget || true

# ROPgadget
RUN pip3 install --break-system-packages ROPGadget || true

# Remove PEP 668 marker so agent can pip install at runtime without --break-system-packages
RUN rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED

# ============================================================
# Phase 9: Binary Tools (ysoserial)
# ============================================================
RUN mkdir -p /opt/tools/ysoserial && \
    wget -qO /opt/tools/ysoserial/ysoserial-all.jar \
    "https://xget-cfw.fireline.fun/gh/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar" || true

# ============================================================
# Phase 9b: jadx (Android/Java Decompiler)
# ============================================================
RUN JADX_VERSION="1.5.5" && \
    wget -qO /tmp/jadx.zip \
    "https://xget-cfw.fireline.fun/gh/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" && \
    mkdir -p /opt/tools/jadx && \
    unzip -q /tmp/jadx.zip -d /opt/tools/jadx && \
    chmod +x /opt/tools/jadx/bin/jadx /opt/tools/jadx/bin/jadx-gui && \
    ln -sf /opt/tools/jadx/bin/jadx /usr/local/bin/jadx && \
    rm -f /tmp/jadx.zip || true

# ============================================================
# Phase 10: ProjectDiscovery Tools (httpx, katana)
# ============================================================
RUN set -x; \
    arch=$(uname -m); \
    if [ "$arch" = "x86_64" ]; then platform="linux_amd64"; \
    elif [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then platform="linux_arm64"; \
    else platform="linux_amd64"; fi; \
    # Katana
    KATANA_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/katana/releases/latest \
      | grep -o '"browser_download_url": *"[^"]*"' | grep "${platform}.zip" | head -1 | cut -d'"' -f4) || true; \
    if [ -n "$KATANA_URL" ]; then \
      KATANA_URL_XGET=$(echo "$KATANA_URL" | sed 's|https://github.com/|https://xget-cfw.fireline.fun/gh/|'); \
      wget -qO /tmp/katana.zip "$KATANA_URL_XGET" && \
      unzip -q /tmp/katana.zip -d /tmp/katana_extracted && \
      find /tmp/katana_extracted -type f -name katana -exec mv {} /usr/local/bin/katana \; && \
      chmod +x /usr/local/bin/katana; \
      rm -rf /tmp/katana.zip /tmp/katana_extracted; \
    fi; \
    # Httpx
    HTTPX_URL=$(curl -sL https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
      | grep -o '"browser_download_url": *"[^"]*"' | grep "${platform}.zip" | head -1 | cut -d'"' -f4) || true; \
    if [ -n "$HTTPX_URL" ]; then \
      HTTPX_URL_XGET=$(echo "$HTTPX_URL" | sed 's|https://github.com/|https://xget-cfw.fireline.fun/gh/|'); \
      wget -qO /tmp/httpx.zip "$HTTPX_URL_XGET" && \
      unzip -q /tmp/httpx.zip -d /tmp/httpx_extracted && \
      find /tmp/httpx_extracted -type f -name httpx -exec mv {} /usr/local/bin/httpx \; && \
      chmod +x /usr/local/bin/httpx; \
      rm -rf /tmp/httpx.zip /tmp/httpx_extracted; \
    fi; \
    echo "Done installing ProjectDiscovery tools"

# ============================================================
# Phase 11: Wrapper Scripts
# ============================================================
RUN echo '#!/bin/bash\npython3 /opt/tools/jwt_tool/jwt_tool.py "$@"' > /usr/local/bin/jwt-tool && chmod +x /usr/local/bin/jwt-tool || true && \
    echo '#!/bin/bash\npython3 /opt/tools/tplmap/tplmap.py "$@"' > /usr/local/bin/tplmap && chmod +x /usr/local/bin/tplmap || true && \
    echo '#!/bin/bash\npython3 /opt/tools/XSStrike/xsstrike.py "$@"' > /usr/local/bin/xsstrike && chmod +x /usr/local/bin/xsstrike || true && \
    echo '#!/bin/bash\npython3 /opt/tools/Gopherus/gopherus.py "$@"' > /usr/local/bin/gopherus && chmod +x /usr/local/bin/gopherus || true && \
    echo '#!/bin/bash\n/opt/tools/phpggc/phpggc "$@"' > /usr/local/bin/phpggc && chmod +x /usr/local/bin/phpggc || true && \
    echo '#!/bin/bash\npython3 /opt/tools/RsaCtfTool/RsaCtfTool.py "$@"' > /usr/local/bin/rsactftool && chmod +x /usr/local/bin/rsactftool || true && \
    echo '#!/bin/bash\njava -jar /opt/tools/ysoserial/ysoserial-all.jar "$@"' > /usr/local/bin/ysoserial && chmod +x /usr/local/bin/ysoserial || true

# ============================================================
# Final: Working Directory
# ============================================================
WORKDIR /root

CMD ["/bin/bash"]

# ===================================================================
# chying-full: 工具容器（主程序在宿主机运行，通过 docker exec 调用工具）
# ===================================================================
FROM kali-tools AS chying-full

# 入口脚本
COPY docker/entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

ENV CHYING_IN_CONTAINER=1
EXPOSE 8089 8766

ENTRYPOINT ["/opt/entrypoint.sh"]
