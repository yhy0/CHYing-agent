#!/bin/bash
# Ghidra 自动导入脚本 - 供 reverse_agent 调用
# 用法: ghidra_import.sh <binary_path> [project_name]
#
# 功能:
#   1. 用 analyzeHeadless 导入并分析二进制文件
#   2. 重启 Headless Server 加载该项目
#   3. 返回成功后，MCP 工具即可访问

set -e

BINARY_PATH="$1"
PROJECT_NAME="${2:-GhidraProject}"
PROJECT_DIR="/tmp/ghidra_projects"
GHIDRA_HOME="/opt/tools/ghidra"
GHIDRA_MCP_DIR="/opt/tools/ghidra-mcp"

if [ -z "$BINARY_PATH" ]; then
    echo '{"error": "Usage: ghidra_import.sh <binary_path> [project_name]"}'
    exit 1
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "{\"error\": \"File not found: $BINARY_PATH\"}"
    exit 1
fi

# 创建项目目录
mkdir -p "$PROJECT_DIR"

# 获取文件名（不含路径）
BINARY_NAME=$(basename "$BINARY_PATH")

echo "[ghidra_import] Importing $BINARY_NAME into project $PROJECT_NAME ..." >&2

# 1. 用 analyzeHeadless 导入并分析
"${GHIDRA_HOME}/support/analyzeHeadless" \
    "$PROJECT_DIR" "$PROJECT_NAME" \
    -import "$BINARY_PATH" \
    -overwrite \
    -scriptPath "${GHIDRA_MCP_DIR}/ghidra_scripts" \
    2>&1 | grep -E "(INFO|ERROR|REPORT)" >&2 || true

# 检查项目是否创建成功
if [ ! -f "${PROJECT_DIR}/${PROJECT_NAME}.gpr" ]; then
    echo '{"error": "Failed to create Ghidra project"}'
    exit 1
fi

# 2. 停止现有的 Headless Server
pkill -f "GhidraMCPHeadlessServer" 2>/dev/null || true
sleep 2

# 3. 构建 classpath
CLASSPATH="${GHIDRA_MCP_DIR}/GhidraMCP.jar"
for jar in ${GHIDRA_HOME}/Ghidra/Framework/*/lib/*.jar \
           ${GHIDRA_HOME}/Ghidra/Features/*/lib/*.jar \
           ${GHIDRA_HOME}/Ghidra/Processors/*/lib/*.jar; do
    [ -f "$jar" ] && CLASSPATH="${CLASSPATH}:${jar}"
done
for jar in ${GHIDRA_MCP_DIR}/lib/*.jar; do
    [ -f "$jar" ] && CLASSPATH="${CLASSPATH}:${jar}"
done

# 4. 启动新的 Headless Server（加载项目）
echo "[ghidra_import] Starting Headless Server with project $PROJECT_NAME ..." >&2
java -Xmx4g -XX:+UseG1GC \
    -Dghidra.home=${GHIDRA_HOME} \
    -Dapplication.name=GhidraMCP \
    -classpath "${CLASSPATH}" \
    com.xebyte.headless.GhidraMCPHeadlessServer \
    --port 8089 --bind 0.0.0.0 \
    --project "${PROJECT_DIR}/${PROJECT_NAME}.gpr" \
    > /tmp/ghidra-mcp-headless.log 2>&1 &

HEADLESS_PID=$!

# 5. 等待 Headless Server 启动
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8089/check_connection >/dev/null 2>&1; then
        echo "[ghidra_import] Headless Server ready (PID=$HEADLESS_PID)" >&2
        
        # 输出 JSON 结果
        echo "{\"success\": true, \"project\": \"$PROJECT_NAME\", \"binary\": \"$BINARY_NAME\", \"project_path\": \"${PROJECT_DIR}/${PROJECT_NAME}.gpr\"}"
        exit 0
    fi
    sleep 2
done

echo '{"error": "Headless Server failed to start within 60 seconds"}'
exit 1
