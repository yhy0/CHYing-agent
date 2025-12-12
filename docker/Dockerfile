# Dockerfile for Kali Linux Security Tools Environment
# Kali Rolling base with comprehensive pentesting tools

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install system packages, Python, and common security tools
RUN set -eux; \
    # 国内镜像优先，然后是国外镜像
    #mirrors="ftp.acc.umu.se/mirror/kali.org/kali mirror.math.princeton.edu/pub/kali kali.mirror.garr.it/mirrors/kali mirror.pit.teraswitch.com/kali"; \
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
    python3 \
    python3-venv \
    python3-pip \
    python-is-python3 \
    # Java runtime for ZAP/Burp
    openjdk-21-jre-headless \
    # Security tools
    nmap \
    sqlmap \
    gobuster \
    curl \
    netcat-traditional \
    tcpdump \
    git \
    perl \
    gnupg2 \
    wget \
    # Perl SSL/TLS modules for Nikto HTTPS support
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libcrypt-ssleay-perl \
    libssl-dev \
    ca-certificates \
    # Network tools
    iputils-ping \
    dnsutils \
    iproute2 \
    net-tools \
    traceroute \
    # Additional essential tools
    jq \
    unzip \
    tree \
    sudo \
    # Web scanners
    nikto \
    whatweb \
    wafw00f \
    zaproxy \
    burpsuite \
    # Recon and DNS
    amass \
    subfinder \
    dnsrecon \
    dnsenum \
    theharvester \
    # Web fuzzing & directories
    ffuf \
    feroxbuster \
    dirb \
    arjun \
    wapiti \
    wfuzz \
    wpscan \
    # Network scanning
    masscan \
    naabu \
    # SMB/NetBIOS
    smbclient \
    smbmap \
    nbtscan \
    python3-impacket \
    # SNMP/Discovery
    arp-scan \
    ike-scan \
    onesixtyone \
    snmpcheck \
    netdiscover \
    # Utilities
    hping3 \
    socat \
    proxychains4 \
    sslscan \
    seclists \
    # Web app helpers
    commix \
    xsser \
    hashid \
    # ProjectDiscovery vuln scanner
    nuclei \
    # Auth/bruteforce
    hydra \
    medusa \
    ncrack \
    # Content and metadata
    libimage-exiftool-perl \
    cewl \
    # WebDAV testing
    cadaver \
    davtest \
    # SSL/TLS testing
    sslyze \
    testssl.sh \
    # Extra recon/webapp scanners
    gospider \
    httprobe \
    subjack \
    knockpy \
    joomscan \
    wig \
    uniscan \
    dirsearch \
    skipfish \
    # Offensive frameworks
    metasploit-framework \
    # Go toolchain for ProjectDiscovery/tomnomnom tools
    golang \
    # Rust toolchain for building Python packages with native extensions
    rustc \
    cargo \
    # Node.js for GraphQL tools
    nodejs \
    npm \
    # Python build tools for pip packages
    python3-dev \
    build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Create working directories
RUN mkdir -p /opt/tools /root/go

# Environment variables for Go
ENV GOPATH="/root/go"
ENV GOCACHE="/root/go/.cache"
ENV PATH="/root/go/bin:$PATH"
# 使用国内 Go 代理加速
ENV GOPROXY="https://goproxy.cn,https://mirrors.aliyun.com/goproxy/,direct"

# Pre-install Go-based recon tools
# assetfinder (tomnomnom) builds quickly from source
RUN go install github.com/tomnomnom/assetfinder@latest

# Install additional security tools
# GraphQL Clairvoyance - GraphQL schema enumeration (使用 Xget 加速)
RUN git clone https://xget-cfw.fireline.fun/gh/nikitastupin/clairvoyance.git /opt/tools/clairvoyance || true && \
    if [ -d /opt/tools/clairvoyance ]; then \
      cd /opt/tools/clairvoyance && \
      python3 -m venv venv && \
      . venv/bin/activate && \
      pip install . || true; \
    fi

# JWT Tool - JWT analysis and manipulation (使用 Xget 加速)
RUN git clone https://xget-cfw.fireline.fun/gh/ticarpi/jwt_tool.git /opt/tools/jwt_tool || true && \
    if [ -f /opt/tools/jwt_tool/jwt_tool.py ]; then chmod +x /opt/tools/jwt_tool/jwt_tool.py; fi

# tplmap - Server-Side Template Injection scanner (使用 Xget 加速)
RUN git clone https://xget-cfw.fireline.fun/gh/epinna/tplmap.git /opt/tools/tplmap || true && \
    if [ -f /opt/tools/tplmap/tplmap.py ]; then chmod +x /opt/tools/tplmap/tplmap.py; fi

# Install Python packages for security tools (use --break-system-packages for Kali)
RUN pip3 install --break-system-packages --ignore-installed requests aiohttp jinja2 'httpx[cli]' ratelimit pycryptodomex -i https://xget-cfw.fireline.fun/pypi/simple/

# Create wrapper scripts for easy access
RUN ([ -d /opt/tools/clairvoyance ] && echo '#!/bin/bash\ncd /opt/tools/clairvoyance && source venv/bin/activate && python -m clairvoyance "$@"' > /usr/local/bin/clairvoyance && chmod +x /usr/local/bin/clairvoyance) || true && \
    ([ -f /opt/tools/jwt_tool/jwt_tool.py ] && echo '#!/bin/bash\npython3 /opt/tools/jwt_tool/jwt_tool.py "$@"' > /usr/local/bin/jwt-tool && chmod +x /usr/local/bin/jwt-tool) || true && \
    ([ -f /opt/tools/tplmap/tplmap.py ] && echo '#!/bin/bash\npython3 /opt/tools/tplmap/tplmap.py "$@"' > /usr/local/bin/tplmap && chmod +x /usr/local/bin/tplmap) || true

# httpx and katana from ProjectDiscovery - use prebuilt binaries (使用 Xget 加速)
RUN set -eux; \
    arch=$(uname -m); \
    if [ "$arch" = "x86_64" ]; then platform="linux_amd64"; \
    elif [ "$arch" = "aarch64" ] || [ "$arch" = "arm64" ]; then platform="linux_arm64"; \
    else platform="linux_amd64"; fi; \
    # 使用 Xget 加速 GitHub API 访问
    KATANA_URL=$(curl -s https://api.github.com/repos/projectdiscovery/katana/releases/latest \
      | grep -Eo '"browser_download_url"\s*:\s*"[^"]*' | cut -d '"' -f4 \
      | grep -E "${platform}\\.zip$" | head -n1); \
    HTTPX_URL=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
      | grep -Eo '"browser_download_url"\s*:\s*"[^"]*' | cut -d '"' -f4 \
      | grep -E "${platform}\\.zip$" | head -n1); \
    echo "Fetching: $KATANA_URL"; \
    echo "Fetching: $HTTPX_URL"; \
    # 将下载链接转换为 Xget 加速链接
    KATANA_URL_XGET=$(echo "$KATANA_URL" | sed 's|https://github.com/|https://xget-cfw.fireline.fun/gh/|'); \
    HTTPX_URL_XGET=$(echo "$HTTPX_URL" | sed 's|https://github.com/|https://xget-cfw.fireline.fun/gh/|'); \
    wget -qO /tmp/katana.zip "$KATANA_URL_XGET"; \
    wget -qO /tmp/httpx.zip "$HTTPX_URL_XGET"; \
    rm -rf /tmp/katana_extracted /tmp/httpx_extracted; \
    mkdir -p /tmp/katana_extracted /tmp/httpx_extracted; \
    unzip -q /tmp/katana.zip -d /tmp/katana_extracted || true; \
    unzip -q /tmp/httpx.zip -d /tmp/httpx_extracted || true; \
    # Find and install binaries
    find /tmp/katana_extracted -type f -name katana -exec mv {} /usr/local/bin/katana \; || true; \
    find /tmp/httpx_extracted -type f -name httpx -exec mv {} /usr/local/bin/httpx \; || true; \
    chmod +x /usr/local/bin/katana /usr/local/bin/httpx || true; \
    rm -rf /tmp/katana_extracted /tmp/httpx_extracted /tmp/katana.zip /tmp/httpx.zip

# Set working directory
WORKDIR /root

# Default command: start bash shell
CMD ["/bin/bash"]