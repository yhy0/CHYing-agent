"""
Claude SDK Agent 模块

提供基于 Claude Code SDK 的 Agent 基类和工具函数。

## 模块组成

- **base.py**: BaseClaudeAgent 基类，提供会话管理、Options 构建、结构化输出
- **hooks.py**: Hook 工厂函数（PreToolUse/PostToolUse/SubagentStop/PreCompact）及辅助工具
- **token_tracking.py**: Token 用量追踪与格式化工具
- **reflection.py**: 反思机制（ReflectionTracker、反思 agent 调度、报告持久化）
- **web_terminal.py**: Web Terminal 初始化脚本（WT_INIT_SCRIPT）和 PostToolUse 注入逻辑
- **file_guards.py**: 文件读取保护模块，防止大文件或二进制文件浪费 token
- **schemas.py**: 结构化输出 Schema 定义（Orchestrator 输出）
- **session_parser.py**: Session JSONL 解析器，用于解析 Agent 执行过程

## 使用示例

### 创建自定义 Agent

```python
from chying_agent.claude_sdk import BaseClaudeAgent

class MyAgent(BaseClaudeAgent):
    def _get_mcp_servers(self):
        # 返回 MCP 服务器配置字典，支持多个服务器
        return {
            "server1": {"type": "sse", "url": "http://localhost:8000/sse"},
            "server2": {"type": "stdio", "command": "python", "args": ["-m", "my_mcp"]},
        }

    def _get_allowed_tools(self) -> list[str]:
        return ["mcp__server1__tool1", "mcp__server2__tool2"]

    def _get_agent_type(self) -> str:
        return "MyAgent"

# 使用
agent = MyAgent(model="deepseek-chat", system_prompt="你是一个助手")
result = await agent.execute("帮我分析这个问题")
```

### 使用结构化输出

```python
from chying_agent.claude_sdk import BaseClaudeAgent, StructuredOutput

class MyStructuredAgent(BaseClaudeAgent):
    def _get_output_schema(self):
        return {
            "type": "object",
            "properties": {
                "analysis": {"type": "string"},
                "confidence": {"type": "number"}
            },
            "required": ["analysis", "confidence"]
        }

    # ... 其他抽象方法实现

# 使用
agent = MyStructuredAgent(...)
result: StructuredOutput = await agent.execute_structured("分析这个问题")
print(result.data)  # {"analysis": "...", "confidence": 0.9}
print(result.raw_text)  # 思考过程文本
```

### 解析 Session 文件

```python
from chying_agent.claude_sdk import (
    SessionParser,
    parse_session_file,
    list_sessions_in_project,
    build_session_jsonl_path,
)

# 列出项目中的所有会话
sessions = list_sessions_in_project()
for s in sessions:
    print(f"{s['session_id']}: {s['message_count']} 条消息")

# 通过 session_id 查找 JSONL 文件
jsonl_path = build_session_jsonl_path("session-abc123")

# 解析 JSONL 文件
if jsonl_path:
    parser = SessionParser(str(jsonl_path))
    result = parser.parse()
    for step in result["steps"]:
        print(f"[{step['type']}] {step.get('content', step.get('tool', ''))}")
```
"""

from .base import (
    BaseClaudeAgent,
    StructuredOutput,
    ResponseStreamResult,
    SettingSource,
    create_pre_tool_use_hook,
    create_post_tool_use_hook,
    build_env_config,
)

from .reflection import (
    ReflectionTracker,
    extract_dead_ends,
    extract_prior_findings,
)

from .web_terminal import (
    WT_INIT_SCRIPT,
    build_wt_additional_context,
)

from .file_guards import (
    FILE_SIZE_THRESHOLD_KB,
    FILE_SIZE_THRESHOLD_BYTES,
    BINARY_EXTENSIONS,
    get_file_metadata,
    check_file_read,
)

from .schemas import (
    ORCHESTRATOR_OUTPUT_SCHEMA,
)

from .session_parser import (
    SessionParser,
    parse_session_file,
    get_session_steps,
)

from .session_utils import (
    get_claude_projects_dir,
    get_project_path_for_cwd,
    find_project_path,
    build_session_jsonl_path,
    list_sessions_in_project,
    find_subagent_files,
    DEFAULT_PROJECT_KEYWORD,
)

from .mcp_tools import (
    get_chying_sdk_mcp_servers,
)

from .wss_terminal_client import (
    get_session_manager,
    cleanup_session_manager,
    WssSessionManager,
)

__all__ = [
    # base.py
    "BaseClaudeAgent",
    "StructuredOutput",
    "ResponseStreamResult",
    "SettingSource",
    "create_pre_tool_use_hook",
    "create_post_tool_use_hook",
    "build_env_config",
    # reflection.py
    "ReflectionTracker",
    "extract_dead_ends",
    "extract_prior_findings",
    # web_terminal.py
    "WT_INIT_SCRIPT",
    "build_wt_additional_context",
    # file_guards.py
    "FILE_SIZE_THRESHOLD_KB",
    "FILE_SIZE_THRESHOLD_BYTES",
    "BINARY_EXTENSIONS",
    "get_file_metadata",
    "check_file_read",
    # schemas.py
    "ORCHESTRATOR_OUTPUT_SCHEMA",
    # session_utils.py
    "get_claude_projects_dir",
    "get_project_path_for_cwd",
    "find_project_path",
    "build_session_jsonl_path",
    "list_sessions_in_project",
    "find_subagent_files",
    "DEFAULT_PROJECT_KEYWORD",
    # session_parser.py
    "SessionParser",
    "parse_session_file",
    "get_session_steps",
    # mcp_tools.py
    "get_chying_sdk_mcp_servers",
    # wss_terminal_client.py
    "get_session_manager",
    "cleanup_session_manager",
    "WssSessionManager",
]
