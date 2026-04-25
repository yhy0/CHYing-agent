#!/bin/bash
# 启动 CHYing Agent Web Dashboard（一体化模式）
# 先构建前端，再由 FastAPI 统一托管静态文件

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_UI_DIR="$ROOT_DIR/web-ui"

echo "========================================"
echo "  CHYing Agent Web Dashboard"
echo "========================================"

# 构建前端
echo ""
echo "📦 构建前端..."
cd "$WEB_UI_DIR"
npm install
npm run build
cd "$ROOT_DIR"

echo ""
echo "🚀 启动 Web Dashboard: http://localhost:8080"
echo ""

uv run main.py --dashboard --skip-preflight
