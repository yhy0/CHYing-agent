# ChYing 被动扫描服务 — 部署与集成指南

## 概述

ChYing CLI 是 [ChYing](https://github.com/yhy0/ChYing) 的无头模式，提供：
- **HTTP/HTTPS 代理**：捕获经过的所有 Web 流量
- **被动扫描**：自动检测 SQL 注入、XSS、敏感信息泄露等漏洞
- **MCP 接口**：Agent 通过 MCP 工具查询扫描结果
- **Session 隔离**：多 Agent 并发时互不干扰

```
Agent (CHYing-agent)
  │
  ├── 浏览器 / HTTP 请求 ──proxy──> ChYing CLI (代理 + 被动扫描)
  │                                      │
  │                                      ├── 自动发现漏洞
  │                                      └── 存储到 SQLite
  │
  └── MCP 调用 ──────────────────────> ChYing MCP Server
                                         │
                                         └── 查询漏洞 / 流量 / 状态
```

---

## 一、部署 ChYing CLI

### 方式一：Docker 部署（推荐）

```bash
cd /path/to/ChYing

# 构建镜像
docker build -f Dockerfile.cli -t chying-cli:latest .

# 启动服务
docker compose -f docker-compose.cli.yml up -d
```

默认端口：
- `9080` — HTTP 代理
- `9090` — MCP SSE 服务（路径 `/mcp`）

自定义端口：

```bash
docker run -d \
  --name chying-cli \
  -p 19080:19080 \
  -p 19090:19090 \
  -v chying-data:/root/.config/ChYing \
  chying-cli:latest \
  serve --proxy-port 19080 --mcp-port 19090 --bind 0.0.0.0
```

### 方式二：本地运行

```bash
cd /path/to/ChYing

# 编译
go build -o chying-cli ./cmd/chying-cli/

# 启动
./chying-cli serve --proxy-port 9080 --mcp-port 9090

# 静默模式（不在终端打印流量）
./chying-cli serve --quiet
```

### 验证服务正常

```bash
# 检查代理
curl -x http://127.0.0.1:9080 http://httpbin.org/get

# 检查 MCP（应返回 JSON-RPC 错误，说明端点可达）
curl http://127.0.0.1:9090/mcp
```

---

## 二、与 CHYing-agent Docker 网络集成

当 CHYing-agent 的 Kali 容器和 ChYing CLI 都跑在 Docker 里时，需要确保网络互通。

### 修改 `docker/docker-compose.yml`

```yaml
services:
  # === 新增：ChYing 被动扫描服务 ===
  chying-scanner:
    image: chying-cli:latest
    container_name: chying-scanner
    ports:
      - "9080:9080"
      - "9090:9090"
    volumes:
      - chying-data:/root/.config/ChYing
    command: ["serve", "--proxy-port", "9080", "--mcp-port", "9090", "--bind", "0.0.0.0"]
    restart: unless-stopped
    networks:
      - agent-net

  chying-agent-docker:
    # ... 现有配置 ...
    environment:
      - TZ=Asia/Shanghai
      - LANG=C.UTF-8
      - DISPLAY=:99
      - VNC_PASSWORD=chy86Yghb*ing
      # === 新增：让容器内所有 HTTP 工具自动走 ChYing 代理 ===
      - HTTP_PROXY=http://chying-scanner:9080
      - HTTPS_PROXY=http://chying-scanner:9080
      - NO_PROXY=localhost,127.0.0.1
    networks:
      - agent-net

networks:
  agent-net:
    driver: bridge

volumes:
  chying-data:
    driver: local
```

这样 Kali 容器内的 `curl`、`sqlmap`、`python requests` 等所有 HTTP 工具自动走代理，被动扫描无感捕获。

---

## 三、MCP 配置集成

### 方法一：在 `.mcp.json` 中添加 ChYing MCP Server

在 `agent-work/.mcp.json` 中添加：

```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"]
    },
    "chying-scanner": {
      "type": "http",
      "url": "http://chying-scanner:9090/mcp",
      "_description": "ChYing 被动扫描服务 — 查询流量、漏洞、扫描状态"
    }
  }
}
```

> **注意**：如果是本地运行（非 Docker），URL 改为 `http://127.0.0.1:9090/mcp`

### 方法二：环境变量

```bash
export CHYING_MCP_URL=http://chying-scanner:9090/mcp
```

在代码中根据此环境变量动态添加 MCP server。

---

## 四、Agent 使用流程

Agent 拿到 ChYing MCP 工具后，典型工作流：

### 1. 注册 Session

```
Agent 调用: register_session(targets='["target.com"]', description="SRC测试")
返回: { "session_id": "abc-123", "targets": ["target.com"], ... }
```

### 2. 配置代理 Header

Agent 在所有 HTTP 请求中附带 Session 标识：

```bash
# 在 Docker 容器内执行命令时
curl -H "X-ChYing-Session: abc-123" http://target.com/api/users

# 或者 Python
import requests
requests.get("http://target.com", headers={"X-ChYing-Session": "abc-123"},
             proxies={"http": "http://chying-scanner:9080"})
```

如果通过环境变量 `HTTP_PROXY` 设了全局代理，只需加 header 即可。

### 3. 正常操作目标

Agent 浏览网页、发请求、跑工具——所有 HTTP 流量自动被 ChYing 捕获和扫描。

### 4. 查询扫描结果

```
# 查看扫描状态
Agent 调用: get_scan_status(session_id="abc-123")

# 增量查询新发现
Agent 调用: get_new_findings_since(since="2026-03-31T14:00:00Z", session_id="abc-123")

# 查看所有漏洞
Agent 调用: get_vulnerabilities(session_id="abc-123")

# 查看流量列表
Agent 调用: get_http_history(session_id="abc-123", limit="50")

# 查看完整请求/响应
Agent 调用: get_traffic_detail(hid="42")
```

### 5. 关闭 Session

```
Agent 调用: close_session(session_id="abc-123")
返回: { "closed": true, "total_requests": 234, "total_vulns": 3 }
```

---

## 五、MCP 工具完整列表

### 查询工具

| Tool | 说明 | 关键参数 |
|------|------|----------|
| `get_http_history` | 流量列表（分页） | `session_id`, `limit`, `offset` |
| `get_traffic_detail` | 完整请求/响应 | `hid` 或 `id` |
| `get_traffic_by_host` | 按域名查流量 | `host`, `session_id` |
| `query_by_dsl` | DSL 高级查询 | `dsl` |
| `get_hosts` | 所有域名 | `session_id` |
| `get_vulnerabilities` | 漏洞列表 | `session_id`, `limit`, `offset` |
| `get_statistics` | 统计信息 | `session_id` |
| `get_current_project` | 当前项目信息 | — |

### Session 管理

| Tool | 说明 | 关键参数 |
|------|------|----------|
| `register_session` | 注册扫描会话 | `targets` (JSON数组), `description` |
| `configure_session` | 修改会话目标 | `session_id`, `add_targets`, `remove_targets` |
| `close_session` | 关闭会话 | `session_id` |

### 实时状态

| Tool | 说明 | 关键参数 |
|------|------|----------|
| `get_scan_status` | 扫描状态 | `session_id` |
| `get_new_findings_since` | 增量查询 | `since` (ISO 8601), `session_id`, `type` |

### 主动测试

| Tool | 说明 | 关键参数 |
|------|------|----------|
| `send_request` | 发送自定义请求 | `url`, `method`, `headers`, `body` |
| `run_intruder` | 运行 Intruder 攻击 | `url`, `positions`, `payloads` |

---

## 六、Prompt 集成建议

在 Agent 的 system prompt 中（如 `chying_agent/prompts/orchestrator_strategy.md`）加入被动扫描的使用策略：

```markdown
## 被动扫描策略

当处理 Web 目标时，你有一个被动扫描器（ChYing）在后台自动分析所有 HTTP 流量。

### 工作流
1. **开始前**：调用 `register_session` 注册目标域名
2. **操作时**：正常浏览和测试，所有流量自动被扫描
3. **定期检查**：每完成一个测试阶段后，调用 `get_new_findings_since` 查看新发现
4. **发现漏洞时**：用 `get_traffic_detail` 查看完整请求/响应，理解漏洞上下文
5. **结束时**：调用 `close_session` 获取汇总

### 注意
- 被动扫描器只分析 HTTP/HTTPS 流量，PWN/Crypto 题不走代理
- 所有 HTTP 请求附带 `X-ChYing-Session: <session_id>` header
- 增量查询用 `get_new_findings_since`，避免重复获取全量数据
```

---

## 七、故障排查

### 代理无法连接

```bash
# 检查 ChYing 容器状态
docker logs chying-scanner

# 测试网络连通性（从 agent 容器内）
docker exec chying-agent-docker curl -x http://chying-scanner:9080 http://httpbin.org/get
```

### MCP 连不上

```bash
# 检查 MCP 端口
curl http://localhost:9090/mcp

# 检查容器间 DNS
docker exec chying-agent-docker nslookup chying-scanner
```

### CA 证书问题（HTTPS 流量）

ChYing 使用自签 CA 证书代理 HTTPS。证书位于容器内 `~/.config/ChYing/proxify_data/`：

```bash
# 导出 CA 证书到 agent 容器
docker cp chying-scanner:/root/.config/ChYing/proxify_data/ca.crt /tmp/chying-ca.crt
docker cp /tmp/chying-ca.crt chying-agent-docker:/usr/local/share/ca-certificates/chying-ca.crt
docker exec chying-agent-docker update-ca-certificates

# 或者忽略证书验证（开发环境）
export PYTHONHTTPSVERIFY=0
export CURL_CA_BUNDLE=""
```

---

## 八、已知限制

1. **漏洞 Session 关联**：被动扫描发现的漏洞暂未关联到 session_id（需要改 Jie 扫描管道），`get_vulnerabilities(session_id=X)` 可能漏掉部分结果。
2. **非 HTTP 流量**：PWN、Crypto 等非 HTTP 场景不走代理，被动扫描器不参与。
3. **Session 非持久化**：ChYing CLI 重启后 session 信息丢失，Agent 需要重新注册。流量和漏洞数据在 SQLite 中持久保存。
