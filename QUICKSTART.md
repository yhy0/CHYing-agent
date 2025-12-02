
> **⚠️ 版本说明**
>
> 当前代码为**腾讯云黑客松比赛特定版本**，包含比赛 API 调用、题目管理等竞赛专用逻辑。
>
> 计划在近期重构为**通用版本**，届时将：
> - 移除比赛专用 API，改为通用的目标配置
> - 支持自定义渗透目标（IP/URL）
> - 提供更灵活的任务配置方式
>
> 敬请关注后续更新。

## 快速开始

### 1. 环境准备

```bash
# 克隆项目
git clone https://github.com/yhy0/CHYing-agent
cd CHYing-agent

# 安装依赖
uv sync 
```

### 2. 配置环境变量

```bash
cp .env.example .env

# 编辑 .env 文件
DEEPSEEK_API_KEY=sk-xxx
DOCKER_CONTAINER_NAME=kali-xxx
```

### 3. 启动 Docker 容器

```bash
cd docker
docker-compose up -d
```

### 4. 运行 Agent

```bash
uv run main.py
```

---

## 关键配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MAX_ATTEMPTS` | 70 | 单题最大尝试次数 |
| `MAX_CONCURRENT_TASKS` | 8 | 最大并发任务数 |
| `SINGLE_TASK_TIMEOUT` | 900 | 单题超时（秒） |
| `AUTO_SUBMIT_FLAG` | true | 自动 FLAG 提交（兜底） |
| `FETCH_INTERVAL_SECONDS` | 600 | 拉取题目间隔（秒） |

---

## 项目结构

```
CHYing-agent/
├── main.py                    # 主程序入口
├── chying_agent/            # 核心代码
│   ├── graph.py               # LangGraph 状态机
│   ├── state.py               # 状态定义
│   ├── scheduler.py           # 调度器
│   ├── retry_strategy.py      # 重试策略
│   ├── challenge_solver.py    # 解题逻辑
│   ├── langmem_memory.py      # 记忆系统
│   ├── tools/                 # LangChain 工具
│   │   ├── shell.py           # Shell 命令执行
│   │   ├── shell_enhanced.py  # Python PoC 执行
│   │   └── competition_api_tools.py  # 比赛 API
│   └── executor/              # 命令执行器
│       ├── docker_native.py   # Docker 执行器
│       └── microsandbox.py    # 沙箱执行器
└── docker/                    # Docker 配置
    └── docker-compose.yml
```

---

## 致谢

- [LangGraph](https://github.com/langchain-ai/langgraph) - 工作流编排框架
- [LangMem](https://github.com/langchain-ai/langmem) - 记忆系统
- [Langfuse](https://langfuse.com/) - LLM 可观测性平台
- [DeepSeek](https://www.deepseek.com/) - 主 LLM 模型
- [腾讯云黑客松只能挑战赛](https://zc.tencent.com/competition/competitionHackathon?code=cha004)

---

## License

MIT License

---

**⚠️ 免责声明**：本项目仅用于教育和研究目的，请勿用于非法用途。使用本项目进行渗透测试时，请确保已获得目标系统的授权。

---
