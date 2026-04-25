#!/bin/bash
# Ghidra + bethington/ghidra-mcp 安装脚本
# 参考官方 Dockerfile: https://github.com/bethington/ghidra-mcp/blob/main/docker/Dockerfile
#
# 升级时需要改：
#   GHIDRA_VERSION, GHIDRA_DATE
#     → https://github.com/NationalSecurityAgency/ghidra/releases
#   GHIDRA_MCP_VERSION
#     → https://github.com/bethington/ghidra-mcp/releases

set -eux

GHIDRA_VERSION="12.0.3"
GHIDRA_DATE="20260210"
GHIDRA_MCP_VERSION="v4.3.0"

# ============================================================
# 1. 下载并安装 Ghidra
# ============================================================
wget -O /tmp/ghidra.zip \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
unzip -q /tmp/ghidra.zip -d /opt/tools/
ln -sf "/opt/tools/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/tools/ghidra

# ============================================================
# 2. 克隆 bethington/ghidra-mcp
# ============================================================
git clone --depth 1 --branch "${GHIDRA_MCP_VERSION}" \
    https://github.com/bethington/ghidra-mcp.git /opt/tools/ghidra-mcp

cd /opt/tools/ghidra-mcp

# ============================================================
# 2.5 修复 bridge 动态工具注册异常（v4.3.0 热修复）
# ============================================================
# 说明：
# - 优先使用仓库内经过验证的 bridge_mcp_ghidra.py（由 Dockerfile 复制到 /tmp）
# - 避免在这里做脆弱的字符串替换（上游代码轻微变化会导致构建失败）
# - 若 /tmp 文件不存在，则保留上游默认 bridge 文件
if [ -f /tmp/bridge_mcp_ghidra.py ]; then
    cp /tmp/bridge_mcp_ghidra.py /opt/tools/ghidra-mcp/bridge_mcp_ghidra.py
    echo "[install_ghidra] Applied project bridge_mcp_ghidra.py override"
else
    echo "[install_ghidra] bridge override not found, using upstream bridge"
fi

# ============================================================
# 3. 安装 Ghidra JARs 到 Maven 本地仓库
# 参考官方 Dockerfile，只需要 9 个 JAR（不需要 Help）
# ============================================================
GHIDRA_HOME=/opt/tools/ghidra

mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Framework/Generic/lib/Generic.jar \
    -DgroupId=ghidra -DartifactId=Generic -Dversion=${GHIDRA_VERSION} -Dpackaging=jar
mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar \
    -DgroupId=ghidra -DartifactId=SoftwareModeling -Dversion=${GHIDRA_VERSION} -Dpackaging=jar
mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Framework/Project/lib/Project.jar \
    -DgroupId=ghidra -DartifactId=Project -Dversion=${GHIDRA_VERSION} -Dpackaging=jar
mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Framework/Docking/lib/Docking.jar \
    -DgroupId=ghidra -DartifactId=Docking -Dversion=${GHIDRA_VERSION} -Dpackaging=jar
mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Framework/Utility/lib/Utility.jar \
    -DgroupId=ghidra -DartifactId=Utility -Dversion=${GHIDRA_VERSION} -Dpackaging=jar
mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Framework/Gui/lib/Gui.jar \
    -DgroupId=ghidra -DartifactId=Gui -Dversion=${GHIDRA_VERSION} -Dpackaging=jar
mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Framework/FileSystem/lib/FileSystem.jar \
    -DgroupId=ghidra -DartifactId=FileSystem -Dversion=${GHIDRA_VERSION} -Dpackaging=jar
mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Features/Base/lib/Base.jar \
    -DgroupId=ghidra -DartifactId=Base -Dversion=${GHIDRA_VERSION} -Dpackaging=jar
mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Features/Decompiler/lib/Decompiler.jar \
    -DgroupId=ghidra -DartifactId=Decompiler -Dversion=${GHIDRA_VERSION} -Dpackaging=jar

# Help.jar - pom.xml 依赖
# 路径: Framework/Help/lib/Help.jar
mvn -q install:install-file -Dfile=${GHIDRA_HOME}/Ghidra/Framework/Help/lib/Help.jar \
    -DgroupId=ghidra -DartifactId=Help -Dversion=${GHIDRA_VERSION} -Dpackaging=jar

# ============================================================
# 4. 构建 Headless JAR
# ============================================================
mvn clean package -P headless -DskipTests -Dmaven.test.skip=true -q
cp target/GhidraMCP-*.jar /opt/tools/ghidra-mcp/GhidraMCP.jar

# ============================================================
# 5. 安装 Python bridge 依赖
# ============================================================
pip3 install --break-system-packages --ignore-installed \
    "mcp>=1.5.0,<2.0.0" \
    "requests>=2.28.0,<3.0.0" \
    -i https://pypi.tuna.tsinghua.edu.cn/simple/

# ============================================================
# 6. 清理临时文件
# ============================================================
rm -f /tmp/ghidra.zip
rm -rf /root/.m2/repository  # 清理 Maven 缓存，节省镜像空间

echo "[install_ghidra] Ghidra ${GHIDRA_VERSION} installed at /opt/tools/ghidra"
echo "[install_ghidra] GhidraMCP Headless JAR: /opt/tools/ghidra-mcp/GhidraMCP.jar"
echo "[install_ghidra] Python bridge: /opt/tools/ghidra-mcp/bridge_mcp_ghidra.py"
