# 🛡️ Sentinel Agent

AI 驱动的自主渗透测试代理，基于 LangGraph + ToolNode 架构。

---
## 启动 kali 
# 1. 进入 docker 目录
cd /Users/yhy/Desktop/CHYing-agent/docker

# 2. 构建并启动
docker-compose up -d

# 3. 进入容器
docker-compose exec kali-security /bin/bash

# 4. 停止容器
docker-compose down

# 5. 查看日志
docker-compose logs -f

## 📁 项目结构

```
CHYing-agent/
├── main.py                     # 主程序入口
├── pyproject.toml              # 项目配置
├── .env.example                # 环境变量模板
│
├── sentinel_agent/
│   ├── __init__.py
│   ├── config.py               # 配置加载
│   ├── model.py                # LLM 模型创建
│   ├── state.py                # 状态定义（TypedDict）
│   ├── prompts.py              # 系统提示词
│   ├── common.py               # 日志工具
│   ├── graph.py                # LangGraph 构建
│   ├── langmem_memory.py       # 记忆系统核心
│   │
│   ├── core/                   # 核心抽象层
│   │   ├── __init__.py
│   │   ├── constants.py        # 常量定义
│   │   └── singleton.py        # 单例配置管理
│   │
│   ├── executor/               # 命令执行器
│   │   ├── base.py             # 执行器基类
│   │   ├── factory.py          # 执行器工厂
│   │   ├── docker_native.py    # Docker 执行器（Kali Linux）
│   │   └── microsandbox.py     # Microsandbox 执行器（Python PoC）
│   │
│   ├── nodes/                  # LangGraph 节点
│   │   ├── recon_node.py       # 侦察节点
│   │   ├── analysis_node.py    # 分析节点
│   │   ├── exploitation_node.py # 利用节点
│   │   └── post_exploitation_node.py # 后利用节点
│   │
│   └── tools/                  # LangChain 工具
│       ├── shell.py            # Shell 命令执行
│       ├── shell_enhanced.py   # Python PoC 执行
│       ├── memory_tools.py     # 记忆工具（漏洞记录、历史查询）
│       └── competition_api_tools.py # 比赛 API 工具
│
├── tests/                      # 测试文件
├── examples/                   # 示例代码
└── scripts/                    # 启动脚本
```

---

## 🏗️ 架构设计

### LangGraph + ToolNode 架构

本项目采用 **LangGraph 官方推荐的 ToolNode 架构**：

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Recon Node  │────▶│ should_call_ │────▶│   ToolNode      │
│             │     │ tools?       │     │ (自动执行工具)   │
└─────────────┘     └──────────────┘     └─────────────────┘
       │                   │                      │
       │ continue          │                      │ 返回结果
       ▼                   ▼                      ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│Analysis Node│────▶│ should_call_ │────▶│   ToolNode      │
│             │     │ tools?       │     │                 │
└─────────────┘     └──────────────┘     └─────────────────┘
       │
       ▼
┌─────────────┐     ┌──────────────┐
│Exploit Node │────▶│ Conditional  │────▶ END / Post-Exploit
│             │     │ Router       │
└─────────────┘     └──────────────┘
```

**核心特点：**
- ✅ 节点只生成 `AIMessage`，不直接执行工具
- ✅ `ToolNode` 自动处理所有工具调用
- ✅ LLM 完全自主决定何时调用何种工具
- ✅ 使用 `messages` 字段追踪完整对话历史

---

## 🧩 核心组件

### 1. 执行器（Executor）

| 执行器 | 用途 | 环境 |
|--------|------|------|
| `DockerExecutor` | 执行 Shell 命令（nmap, metasploit 等） | Kali Linux 容器 |
| `MicrosandboxExecutor` | 执行 Python PoC 代码 | 隔离沙箱 |

### 2. 节点（Nodes）

所有节点均为 **异步函数**，返回包含 `messages` 的状态更新字典：

- **Recon Node**: 端口扫描、服务识别
- **Analysis Node**: 漏洞分析、工具选择
- **Exploitation Node**: 漏洞利用、载荷执行
- **Post-Exploitation Node**: FLAG 查找、权限维持

### 3. 工具（Tools）

| 工具 | 类型 | 描述 |
|------|------|------|
| `execute_command` | Shell | 在 Docker 容器中执行命令 |
| `execute_python_poc` | Python | 在沙箱中执行 PoC 代码 |
| `add_memory` | 记忆 | 记录漏洞发现 |
| `record_successful_exploit` | 记忆 | 记录成功利用 |
| `record_failed_attempt` | 记忆 | 记录失败尝试 |
| `query_historical_knowledge` | 记忆 | 查询历史经验 |

### 4. 记忆系统

- **LangMem 原生工具**: 自动记忆管理（向量搜索）
- **自定义记忆工具**: 结构化记录（漏洞、利用、失败）
- **运行时缓存**: 快速访问当前会话数据

---

## 🚀 快速开始

### 1. 环境准备

```bash
# 安装依赖
pip install -e .

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件，设置：
# - DEEPSEEK_API_KEY
# - TARGET_IP
# - DOCKER_CONTAINER_NAME
```

### 2. 启动 Docker 容器

```bash
# 启动 Kali Linux 容器
./scripts/start_containers.sh

# 或手动启动
docker run -d --name kali-sandbox kalilinux/kali-rolling tail -f /dev/null
```

### 3. 运行 Agent

```bash
python main.py
```

---

## 📝 配置说明

### 环境变量

| 变量 | 说明 | 示例 |
|------|------|------|
| `DEEPSEEK_API_KEY` | DeepSeek API 密钥 | `sk-xxx` |
| `TARGET_IP` | 目标 IP 地址 | `192.168.1.100` |
| `DOCKER_CONTAINER_NAME` | Docker 容器名称 | `kali-sandbox` |
| `SANDBOX_ENABLED` | 是否启用 Microsandbox | `true` / `false` |
| `COMPETITION_API_TOKEN` | 比赛 API 令牌（可选） | `bearer-xxx` |

---

## 🔧 开发指南

### 添加新工具

1. 在 `sentinel_agent/tools/` 下创建新文件
2. 使用 `@tool` 装饰器定义工具函数
3. 在 `tools/__init__.py` 中导出

```python
from langchain_core.tools import tool

@tool
def my_custom_tool(param: str) -> str:
    """工具描述（LLM 会读取）"""
    # 实现逻辑
    return result
```

### 修改节点逻辑

编辑 `sentinel_agent/nodes/*_node.py` 中的提示词即可，无需修改执行逻辑。

---

## 📊 代码质量

- ✅ 无 linter 错误
- ✅ 模块化设计（executor-tools-nodes 分层）
- ✅ 完整的类型注解（TypedDict）
- ✅ 详细的文档字符串
- ✅ 线程安全的单例模式

---

## 🙏 致谢

- [LangGraph](https://github.com/langchain-ai/langgraph) - 工作流编排
- [LangMem](https://github.com/langchain-ai/langmem) - 记忆系统
- [Microsandbox](https://github.com/microsandbox/microsandbox) - Python 沙箱
- [DeepSeek](https://www.deepseek.com/) - LLM 模型

---

## 📄 许可证

MIT License
