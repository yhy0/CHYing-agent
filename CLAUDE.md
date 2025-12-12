# CLAUDE.md

本文件为 Claude Code 提供项目代码指导。

## 项目概述

**CHYing Agent** - 基于 LangGraph 的 AI 自动化渗透测试 Agent，用于 CTF 比赛。

**核心设计**：双 Agent 协作（顾问 MiniMax + 主攻手 DeepSeek），三个核心工具（execute_command、execute_python_poc、submit_flag）。

## 核心文件

| 文件 | 职责 |
|------|------|
| `main.py` | 入口，支持 `-t 目标` 单题模式和 `-api` 比赛模式 |
| `chying_agent/graph.py` | LangGraph 图构建，advisor_node + main_agent_node + tool_node |
| `chying_agent/state.py` | 状态定义 PenetrationTesterState |
| `chying_agent/challenge_solver.py` | 单题解题逻辑 |
| `chying_agent/tools/` | 工具定义 |

## 运行命令

```bash
uv run main.py -t http://target.com  # 单目标
uv run main.py -api                   # 比赛模式
```

## 关键机制

1. **顾问介入**：任务开始、失败 3/6/9 次、每 5 次定期咨询、主动求助
2. **自动 FLAG 提交**：tool_node 扫描输出自动提交，防止 LLM 漏调 submit_flag
3. **角色互换**：重试时 DeepSeek ↔ MiniMax 轮换

## 修改指南

- **改 Agent 行为**：修改 `graph.py` 中的 `_build_system_prompt()` 或 `_build_main_system_prompt()`
- **加新工具**：在 `tools/` 创建，用 `@tool` 装饰器，在 `__init__.py` 导出
- **不要**：创建新图节点、绕过执行器、直接修改状态

## 协作原则

### Review 时
- 深入分析每个文件的实现细节，不要只看表面
- 检查边界条件、错误处理、并发安全
- 关注代码是否符合项目现有模式

### 新增功能时
- **先搜索**：检查是否已存在类似实现，优先复用
- **质疑必要性**：这个功能真的需要吗？能否用现有能力组合实现？
- **保持极简**：项目核心理念是「少即是多」，避免过度设计

### 独立思考
- 不要总是认可用户意见，发现问题要直接指出
- 如果方案有更好的替代，主动提出
- 技术决策要基于事实，不是讨好

