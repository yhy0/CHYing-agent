#!/bin/bash
# CHYing-agent 工具容器入口脚本
# 启动后台服务（PostgreSQL/Metasploit、GhidraMCP），然后保持容器运行
# 主程序在宿主机运行，通过 docker exec 调用容器内工具

set -e

# ============================================================
# 1. 启动 PostgreSQL + Metasploit 数据库
# ============================================================
if command -v msfconsole >/dev/null 2>&1; then
    echo "[entrypoint] Starting PostgreSQL for Metasploit ..."
    pg_ctlcluster $(pg_lsclusters -h | head -1 | awk '{print $1, $2}') start 2>/dev/null \
        || service postgresql start 2>/dev/null || true
    msfdb init 2>/dev/null || true
    echo "[entrypoint] Metasploit database ready"
fi

# ============================================================
# 2. GhidraMCP Headless Server + Python MCP Bridge
# ============================================================
GHIDRA_MCP_DIR="/opt/tools/ghidra-mcp"
if [ -f "${GHIDRA_MCP_DIR}/GhidraMCP.jar" ]; then
    echo "[entrypoint] Starting GhidraMCP Headless Server (REST on 0.0.0.0:8089) ..."

    GHIDRA_HOME=/opt/tools/ghidra
    CLASSPATH="${GHIDRA_MCP_DIR}/GhidraMCP.jar"
    for jar in ${GHIDRA_HOME}/Ghidra/Framework/*/lib/*.jar \
               ${GHIDRA_HOME}/Ghidra/Features/*/lib/*.jar \
               ${GHIDRA_HOME}/Ghidra/Processors/*/lib/*.jar; do
        [ -f "$jar" ] && CLASSPATH="${CLASSPATH}:${jar}"
    done
    for jar in ${GHIDRA_MCP_DIR}/lib/*.jar; do
        [ -f "$jar" ] && CLASSPATH="${CLASSPATH}:${jar}"
    done

    java -Xmx4g -XX:+UseG1GC \
        -Dghidra.home=${GHIDRA_HOME} \
        -Dapplication.name=GhidraMCP \
        -classpath "${CLASSPATH}" \
        com.xebyte.headless.GhidraMCPHeadlessServer \
        --port 8089 --bind 0.0.0.0 &
    HEADLESS_PID=$!

    echo "[entrypoint] Waiting for Headless Server to start ..."
    for i in $(seq 1 30); do
        if curl -sf http://127.0.0.1:8089/check_connection >/dev/null 2>&1; then
            echo "[entrypoint] GhidraMCP Headless Server ready (PID=$HEADLESS_PID)"
            break
        fi
        sleep 2
    done

    if [ -f "${GHIDRA_MCP_DIR}/bridge_mcp_ghidra.py" ]; then
        echo "[entrypoint] Starting GhidraMCP bridge (SSE on 0.0.0.0:8766) ..."
        cd ${GHIDRA_MCP_DIR}
        python3 bridge_mcp_ghidra.py \
            --transport sse \
            --mcp-host 0.0.0.0 \
            --mcp-port 8766 \
            --ghidra-server "http://127.0.0.1:8089" &
        BRIDGE_PID=$!
        sleep 2
        if kill -0 $BRIDGE_PID 2>/dev/null; then
            echo "[entrypoint] GhidraMCP bridge started (PID=$BRIDGE_PID)"
        else
            echo "[entrypoint] WARNING: GhidraMCP bridge failed to start"
        fi
        cd /root
    fi
fi

# ============================================================
# 3. 保持容器运行
# ============================================================
echo "[entrypoint] Tool container ready, waiting for commands via docker exec ..."
exec tail -f /dev/null
