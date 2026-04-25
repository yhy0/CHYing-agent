#!/usr/bin/env bash
#
# Remote API Benchmark 一键启动脚本（动态容器管理版）
#
# 用法:
#   bash scripts/run_benchmark.sh                              # 跑全部 (1-104)
#   bash scripts/run_benchmark.sh --concurrency 2              # 并发跑
#   bash scripts/run_benchmark.sh --resume                     # 断点续跑
#   bash scripts/run_benchmark.sh --retry-errors               # 重试失败的
#   bash scripts/run_benchmark.sh --benchmarks 1,2,3           # 跑指定题号
#   bash scripts/run_benchmark.sh --range 1-20                 # 跑指定范围
#
# 前置条件:
#   1. .env 配好 LLM_MODEL / LLM_API_KEY / LLM_BASE_URL
#   2. .env 配好 COMPETITION_BASE_URL / COMPETITION_API_TOKEN
#   3. .env 配好 SINGLE_TASK_TIMEOUT (agent 超时)
#   4. Kali 容器在跑 (DOCKER_CONTAINER_NAME)
#   5. 远程 API Server 已空启动（不带 -i）

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Load .env
if [ -f "$PROJECT_DIR/.env" ]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

# Create output dirs
mkdir -p "$PROJECT_DIR/benchmark-results"
mkdir -p "$PROJECT_DIR/logs"

echo "================================================"
echo "  CHYing-Agent Remote API Benchmark Runner"
echo "  (Dynamic Container Management)"
echo "================================================"
echo "  Model:     ${LLM_MODEL:-unknown}"
echo "  API:       ${LLM_BASE_URL:-unknown}"
echo "  Comp URL:  ${COMPETITION_BASE_URL:-NOT SET}"
echo "  Timeout:   ${SINGLE_TASK_TIMEOUT:-not set}s"
echo "  Docker:    ${DOCKER_CONTAINER_NAME:-chying-agent-docker}"
echo "  Writeup:   ${ENABLE_WRITEUP:-1}"
echo "  Args:      $*"
echo "================================================"

# ---- Pre-flight checks ----

# Check competition API config
if [ -z "${COMPETITION_BASE_URL:-}" ]; then
    echo "[ERROR] COMPETITION_BASE_URL not set. Configure it in .env or pass --api-url"
    exit 1
fi
echo "[CHECK] Competition API: ${COMPETITION_BASE_URL}"

if [ -z "${COMPETITION_API_TOKEN:-}" ]; then
    echo "[WARN] COMPETITION_API_TOKEN not set. Pass --api-token or set in .env"
fi

# Check remote API server is reachable
echo -n "[CHECK] Remote API server connectivity... "
if curl -s --connect-timeout 5 "${COMPETITION_BASE_URL}/docs" >/dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED"
    echo "[ERROR] Cannot reach ${COMPETITION_BASE_URL}"
    echo "  Ensure the remote API server is running (e.g. without -i for empty start)"
    exit 1
fi

# Check Kali container (optional but recommended)
CONTAINER="${DOCKER_CONTAINER_NAME:-chying-agent-docker}"
if command -v docker &>/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
    echo "[CHECK] Kali container ($CONTAINER): running"
elif command -v podman &>/dev/null && podman ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
    echo "[CHECK] Kali container ($CONTAINER): running"
else
    echo "[WARN] Kali container ($CONTAINER) not running - docker_exec will fail"
    echo "  Start it first, or benchmark will only use browser-based attacks"
fi

# Check KB knowledge base
echo "[CHECK] Knowledge Base: using compiled_kb (no separate service needed)"


echo ""
# ---- Run benchmark ----

# Force disable writeup for benchmark (save time + cost)
export ENABLE_WRITEUP=0

LOG_FILE="$PROJECT_DIR/benchmark-results/run_$(date +%Y%m%d_%H%M%S).log"

echo "[START] Benchmark starting at $(date)"
echo "[LOG]   Output: $LOG_FILE"
echo "[LOG]   State:  $PROJECT_DIR/benchmark-results/state.json"
echo ""
echo "  To monitor progress:"
echo "    tail -f $LOG_FILE"
echo "    grep '\\[OK\\]\\|\\[FAIL\\]\\|ERROR' $LOG_FILE | wc -l"
echo ""

nohup uv run python scripts/benchmark_runner.py "$@" > "$LOG_FILE" 2>&1 &
PID=$!
echo "$PID" > "$PROJECT_DIR/benchmark-results/benchmark.pid"

sleep 2
if kill -0 "$PID" 2>/dev/null; then
    echo "[OK] Benchmark running in background (PID: $PID)"
    echo "  To stop: kill $PID"
else
    echo "[ERROR] Benchmark failed to start, check: $LOG_FILE"
    tail -20 "$LOG_FILE"
    exit 1
fi
