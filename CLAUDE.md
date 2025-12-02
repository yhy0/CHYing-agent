# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**CHYing Agent** is an AI-powered autonomous penetration testing agent built on LangGraph + ToolNode architecture. It's designed for CTF competitions and security research, using LLM-driven decision-making to autonomously discover and exploit vulnerabilities.

## Core Architecture

### LangGraph ToolNode Pattern

The project follows LangGraph's official recommended architecture:

- **Single Agent Node**: LLM autonomously decides all actions (no predefined phases)
- **ToolNode**: Automatically handles all tool executions
- **Dynamic System Prompts**: State-based guidance instead of multiple nodes
- **Message Flow**: Uses `messages` field to track complete conversation history

**Workflow**: `agent → [tools?] → agent → [tools?] → ... → end`

### Multi-Agent Collaboration (Optional)

The project supports a team-based approach:
- **Advisor Agent** (MiniMax): Provides attack suggestions and alternative perspectives
- **Main Agent** (DeepSeek): Makes final decisions and executes tools
- **Flow**: `advisor → main_agent → [tools?] → advisor → ...`

### Executor System

Two execution environments:

1. **DockerExecutor** (`chying_agent/executor/docker_native.py`)
   - Runs shell commands in Kali Linux container
   - Used for: nmap, sqlmap, metasploit, curl, etc.
   - Configured via `DOCKER_CONTAINER_NAME`

2. **MicrosandboxExecutor** (`chying_agent/executor/microsandbox.py`)
   - Executes Python PoC code in isolated sandbox
   - Used for: HTTP requests, custom exploits, data processing
   - Configured via `SANDBOX_ENABLED`

## Modular Architecture (v2.0)

The project has been fully refactored into a modular architecture for better maintainability:

### Core Modules

1. **`chying_agent/task_manager.py`** - Task lifecycle management
   - Tracks active/completed/failed tasks
   - Manages retry counts and attempt history
   - Determines retry eligibility

2. **`chying_agent/retry_strategy.py`** - Intelligent retry with role swapping
   - Swaps DeepSeek ↔ MiniMax on retry attempts
   - Formats historical failure records
   - Extracts attempt summaries

3. **`chying_agent/challenge_solver.py`** - Single challenge solving logic
   - Auto-reconnaissance injection
   - Historical record inheritance
   - Concurrent semaphore management
   - Complete exception isolation

4. **`chying_agent/task_launcher.py`** - Task creation and launching
   - Checks task status (avoid duplicates)
   - Selects LLM pairs based on retry count
   - Creates async tasks

5. **`chying_agent/scheduler.py`** - Scheduling and monitoring
   - Dynamic slot filling (⭐ key optimization)
   - Periodic challenge fetching
   - Status monitoring
   - Final status reporting

6. **`chying_agent/utils/utils.py`** - Utility functions
   - Challenge fetching
   - Solved challenge filtering

7. **`main_refactored.py`** - Main coordinator (150 lines vs 750+ original)
   - Initialization only
   - Delegates to specialized modules

### Key Optimizations

- **Dynamic Slot Filling**: Tasks complete → immediately check for pending challenges (no 10-minute wait)
- **Role Swapping**: Retry 1 (DeepSeek main) → Retry 2 (MiniMax main) → Retry 3 (DeepSeek main)
- **Historical Inheritance**: Failed methods and key findings passed to retry attempts
- **Exception Isolation**: Single task failure never affects other concurrent tasks

See [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md) for detailed architecture documentation.

## Development Commands

### Environment Setup

```bash
# Install dependencies (using uv)
pip install -e .

# Configure environment
cp .env.example .env
# Edit .env to set:
# - DEEPSEEK_API_KEY
# - DOCKER_CONTAINER_NAME (if using Docker)
# - SILICONFLOW_API_KEY (if using multi-agent mode)
```

### Running the Agent

```bash
# Use refactored version (recommended)
uv run main_refactored.py

# Or use original version
uv run main.py
```

### Docker Management

```bash
# Start Kali Linux container
cd docker
docker-compose up -d

# Enter container
docker-compose exec kali-security /bin/bash

# Stop container
docker-compose down

# View logs
docker-compose logs -f
```

## Key Components

### State Management (`chying_agent/state.py`)

- Uses `TypedDict` for type safety
- Custom reduce functions for list merging (e.g., `merge_by_unique_key`)
- Key fields:
  - `messages`: LangGraph message sequence
  - `challenges`: CTF challenge list from API
  - `current_challenge`: Active target
  - `advisor_suggestion`: Multi-agent collaboration field

### Graph Construction

- **Single Agent**: `chying_agent/graph.py` - `build_graph()`
- **Multi-Agent**: `chying_agent/graph.py` - `build_multi_agent_graph()`

Both use:
- Dynamic system prompts via `_build_system_prompt(state)`
- Conditional routing via `should_continue(state)`
- Memory integration via LangMem

### Tools (`chying_agent/tools/`)

| Tool | Purpose | Executor |
|------|---------|----------|
| `execute_command` | Shell commands | DockerExecutor |
| `execute_python_poc` | Python PoC code | MicrosandboxExecutor |
| `get_challenge_list` | Fetch CTF challenges | Competition API |
| `submit_flag` | Submit FLAG (with auto-validation) | Competition API |
| `view_challenge_hint` | Get hints (penalty) | Competition API |
| `add_memory` | Log findings | LangMem |
| `query_historical_knowledge` | Search memory | LangMem |

**Note**: `submit_flag` includes automatic FLAG format validation to prevent incomplete submissions (e.g., missing closing `}`). See `chying_agent/utils/flag_validator.py` for validation logic.

### Configuration (`chying_agent/config.py`)

- Singleton pattern via `chying_agent/core/singleton.py`
- Environment modes: `competition` (only supported mode)
- Validates required environment variables on startup

## Important Implementation Details

### Adding New Tools

1. Create tool in `chying_agent/tools/`
2. Use `@tool` decorator with clear docstring (LLM reads this)
3. Export in `tools/__init__.py`

Example:
```python
from langchain_core.tools import tool

@tool
def my_custom_tool(param: str) -> str:
    """Tool description for LLM"""
    # Implementation
    return result
```

### Modifying Agent Behavior

**Do NOT create new nodes**. Instead, modify the dynamic system prompt in:
- `chying_agent/graph.py` → `_build_system_prompt()`
- `chying_agent/graph.py` → `ADVISOR_SYSTEM_PROMPT` or `_build_main_system_prompt()`

The LangGraph pattern uses state-based prompts to guide behavior, not separate nodes.

### Memory System

- **LangMem Native**: Automatic vector search and retrieval
- **Custom Tools**: Structured recording (vulnerabilities, exploits, failures)
- **Runtime Cache**: Fast access to current session data

### Failure Detection

The router (`should_continue`) detects common failure patterns:
- Repeated curl quote/escape errors → suggests switching to Python
- Identical repeated commands → prompts for new approach
- Attempt limits: Configurable via `MAX_ATTEMPTS` (default: 70)

### Auto FLAG Submission (Fallback Strategy)

**Problem**: LLMs sometimes find the FLAG but fail to call `submit_flag` correctly. Common mistakes:
- Using `execute_python_poc` to print FLAG instead of calling `submit_flag`
- Writing `submit_flag` in comments but not executing it
- Misunderstanding tool usage

**Solution**: Automatic FLAG extraction and submission in `tool_node` ([graph.py:220-315](chying_agent/graph.py#L220-L315))

**How it works**:
1. After tool execution, scan output for FLAG patterns (`flag{...}` or `FLAG{...}`)
2. If FLAG detected and LLM didn't call `submit_flag` → auto-submit
3. If submission succeeds → immediately end task (set `is_finished=True`)
4. If submission fails → notify LLM and continue

**Configuration**:
- Enable/disable: `AUTO_SUBMIT_FLAG=true` (default: `true`)
- FLAG extraction: `chying_agent/utils/flag_validator.py::extract_flag_from_text()`
- Supports case-insensitive matching and deduplication

**Benefits**:
- Prevents wasted attempts due to LLM tool-calling errors
- Significantly improves success rate (especially with weaker models)
- No downside: only triggers when LLM makes a mistake

## Environment Variables Reference

| Variable | Required | Purpose | Default | Example |
|----------|----------|---------|---------|---------|
| `DEEPSEEK_API_KEY` | Yes | Main LLM API key | - | `sk-xxx` |
| `DEEPSEEK_BASE_URL` | No | API endpoint | `https://api.deepseek.com/v1` | - |
| `LLM_MODEL_NAME` | No | Model name | `deepseek-v3.1-terminus` | - |
| `ENV_MODE` | No | Environment mode | `competition` | - |
| `DOCKER_CONTAINER_NAME` | Conditional | Kali container name | - | `kali-sandbox` |
| `SANDBOX_ENABLED` | No | Enable Microsandbox | `false` | `true`/`false` |
| `SILICONFLOW_API_KEY` | Multi-agent only | Advisor LLM key | - | `sk-xxx` |
| `SILICONFLOW_MODEL` | No | Advisor model | `MiniMaxAI/MiniMax-M2` | - |
| **`MAX_ATTEMPTS`** | No | **单题最大尝试次数** | **70** | `70` |
| **`RECURSION_LIMIT`** | No | **LangGraph 递归限制** | **80** | `80` |
| **`SINGLE_TASK_TIMEOUT`** | No | **单题超时（秒）** | **900** | `900` |
| `FETCH_INTERVAL_SECONDS` | No | 拉取题目间隔（秒） | `600` | `600` |
| `MONITOR_INTERVAL_SECONDS` | No | 状态监控间隔（秒） | `300` | `300` |
| **`AUTO_SUBMIT_FLAG`** | No | **自动 FLAG 提交（兜底）** | **true** | `true`/`false` |
| `ENABLE_SMART_FAILURE_DETECTION` | No | LLM 语义失败检测 | `true` | `true`/`false` |
| `ENABLE_TOOL_SUMMARY` | No | 工具输出总结 | `true` | `true`/`false` |
| `TOOL_SUMMARY_THRESHOLD` | No | 总结阈值（字符） | `5000` | `5000` |
| `MAX_SUMMARY_LENGTH` | No | 最大总结长度（字符） | `10000` | `10000` |

## Code Quality Standards

- Type annotations using `TypedDict` for state
- Async/await for all node functions
- Detailed docstrings explaining LangGraph patterns
- Thread-safe singleton configuration
- No linter errors

## Common Pitfalls

1. **Don't bypass the executor factory** - Always use `get_executor()` or `get_python_executor()`
2. **Don't modify state directly in nodes** - Return state update dictionaries
3. **Don't create new graph nodes for phases** - Use dynamic prompts instead
4. **Don't forget to bind tools to LLM** - Use `llm.bind_tools(all_tools)`
5. **Security**: All commands MUST run in Docker/sandbox - local execution is disabled

## Architecture Rationale

This codebase was refactored (2025-11-09) from a 4-node architecture (Recon/Analysis/Exploitation/Post-Exploitation) to a single-node pattern because:

- LangGraph recommends letting LLM decide workflow, not hardcoding phases
- Reduces complexity and improves flexibility
- Better aligns with ReAct pattern
- Easier to extend with new tools without graph changes
