"""
Claude SDK Agent 基类

提供 Claude Code SDK Agent 的公共功能：
- Hook 创建（PreToolUse/PostToolUse）
- 会话管理（LRU 缓存，带异步锁保护）
- Options 构建
- 异步执行流程
- 结构化输出支持（通过 output_format）

适配自 GangTrace 项目，用于 CHYing-agent CTF 渗透测试场景。
"""

import asyncio
import json
import os
import logging
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Optional,
    Dict,
    Any,
    List,
    Callable,
    Awaitable,
    cast,
    TypeVar,
    Generic,
    Literal,
)

from claude_agent_sdk import (
    ClaudeSDKClient,
    ClaudeAgentOptions,
    HookMatcher,
    # 消息类型
    UserMessage,
    AssistantMessage,
    SystemMessage,
    ResultMessage,
    # 内容块类型
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    ToolResultBlock,
)
from claude_agent_sdk.types import HookEvent, StreamEvent

from ..common import log_tool_event, log_system_event, log_task_event, log_guidance_event, format_tool_source_prefix, format_orchestrator_prefix
from .reflection import (
    ReflectionTracker,
    get_current_log_file_path,
    get_current_work_dir_str,
    persist_session_summary,
    read_reflection_history,
    extract_dead_ends,
)
from .hooks import (
    create_pre_tool_use_hook,
    create_post_tool_use_hook,
    create_subagent_stop_hook,
    load_skill_hints,
    _get_compact_recovery_files,
)
from .token_tracking import (
    _StreamUsageTracker,
    _estimate_cost_from_tokens,
    _get_context_window_size,
    _log_usage_summary,
)

# 泛型类型变量，用于结构化输出
T = TypeVar("T", bound=Dict[str, Any])

# SettingSource 类型别名（模块级定义，避免类内引用问题）
SettingSource = Literal["user", "project", "local"]

# 模块级 logger
_logger = logging.getLogger(__name__)


def _format_data_size(data: Any) -> str:
    """将数据序列化后计算字符大小，返回可读字符串（如 1.2K）"""
    if data is None:
        return "0"
    if isinstance(data, str):
        n = len(data)
    elif isinstance(data, dict):
        n = len(json.dumps(data, ensure_ascii=False))
    else:
        n = len(str(data))
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    elif n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


# Guidance Loop 常量
MAX_GUIDANCE_ROUNDS = 5

SUBAGENT_MAX_TOOL_USES = int(os.environ.get("SUBAGENT_MAX_TOOL_USES", "20"))


def _is_solved(result: "ResponseStreamResult") -> bool:
    """检查结构化输出中 solved 是否为 true。"""
    if not result.structured_data or not isinstance(result.structured_data, dict):
        return False
    solved = result.structured_data.get("solved")
    if solved is None:
        solved = result.structured_data.get("success")
    return bool(solved)



def build_env_config(
    model: str,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    use_local_cli: bool = False,
) -> Dict[str, str]:
    """
    构建环境变量配置

    Args:
        model: 模型名称
        api_key: API 密钥（可选，不传则使用本地 Claude 配置）
        base_url: API 基础 URL（可选，不传则使用本地 Claude 配置）
        use_local_cli: 是否使用本地 CLI 模式。为 True 时不注入任何 API 配置，
                       由 CLI 自行管理认证和模型路由

    Returns:
        环境变量字典（如果不需要覆盖，返回空字典）
    """
    env = {}

    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] = "1"  # 禁用 auto memory（~13K chars system prompt 开销，CTF 单次任务不需要跨会话记忆）
    env["CLAUDE_CODE_DUMP_PROMPTS"] = "1"

    # 同步上下文窗口设置到 CLI，确保 CLI 内置的 auto compact 正确触发
    # 默认 CLI 假设 200K 窗口，对第三方模型（kimi/deepseek 等）过大
    compact_window = os.environ.get("CLAUDE_CODE_AUTO_COMPACT_WINDOW", "")
    if compact_window.strip():
        env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = compact_window.strip()
    compact_pct = os.environ.get("CLAUDE_AUTOCOMPACT_PCT_OVERRIDE", "")
    if compact_pct.strip():
        env["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"] = compact_pct.strip()

    if use_local_cli:
        # 本地 CLI 模式：不注入 API 配置，由 CLI 自行管理
        return env

    # 只有显式传入 API 配置时才设置环境变量
    # 否则完全复用本地 ~/.claude/ 配置
    if api_key:
        env["ANTHROPIC_AUTH_TOKEN"] = api_key

    if base_url:
        # Claude SDK 内部会拼接 /v1/messages 等路径，
        # 如果用户传入的 base_url 已经带了 /v1 后缀，需要剥离以避免重复
        url = base_url.rstrip("/")
        if url.endswith("/v1"):
            url = url[:-3]
        env["ANTHROPIC_BASE_URL"] = url

    # 只有在设置了 API 配置时，才添加模型映射
    # 这样可以让第三方 API 使用自定义模型名
    if env:
        env["ANTHROPIC_MODEL"] = model
        env["ANTHROPIC_DEFAULT_OPUS_MODEL"] = model
        env["ANTHROPIC_DEFAULT_SONNET_MODEL"] = model
        env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = model
        env["CLAUDE_CODE_SUBAGENT_MODEL"] = model

    return env


@dataclass
class ModelSlot:
    """一组 LLM 配置（用于双模型交替运行）。

    Guidance Loop 每轮自动轮换 slot，让两个不同模型交替推理，
    突破单一模型的知识和思维局限。
    """
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    label: str = ""


class StructuredOutput(Generic[T]):
    """
    结构化输出结果包装类

    包含：
    - data: 结构化数据（符合 schema 的字典）
    - raw_text: 原始文本响应（思考过程等）
    - tool_calls: 工具调用列表
    """

    def __init__(
        self,
        data: Optional[T] = None,
        raw_text: str = "",
        tool_calls: Optional[List[Dict[str, Any]]] = None,
    ):
        self.data = data
        self.raw_text = raw_text
        self.tool_calls = tool_calls or []

    def __repr__(self) -> str:
        return f"StructuredOutput(data={self.data}, raw_text_len={len(self.raw_text)}, tool_calls={len(self.tool_calls)})"

    @property
    def has_data(self) -> bool:
        """是否有结构化数据"""
        return self.data is not None

    def get(self, key: str, default: Any = None) -> Any:
        """从结构化数据中获取字段"""
        if self.data is None:
            return default
        return self.data.get(key, default)



class ResponseStreamResult:
    """
    响应流处理结果

    包含从 Claude SDK 响应流中提取的所有信息。
    """

    def __init__(
        self,
        text: str = "",
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        structured_data: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        transcript_path: Optional[str] = None,
        usage: Optional[Dict[str, Any]] = None,
        total_cost_usd: Optional[float] = None,
        is_error: bool = False,
        error_message: Optional[str] = None,
        turn_count: int = 0,
    ):
        self.text = text
        self.tool_calls = tool_calls or []
        self.structured_data = structured_data
        self.session_id = session_id
        self.transcript_path = transcript_path
        self.usage = usage
        self.total_cost_usd = total_cost_usd
        self.is_error = is_error
        self.error_message = error_message
        self.turn_count = turn_count
        self.session_exhausted = False
        self.max_turns_exhausted = False  # SDK max_turns 耗尽（非致命，Guidance Loop 可继续）
        self.transcript_corrupt = False  # transcript 中存在幻觉 tool_use_id 等不兼容内容

    def accumulate_usage(self, other: "ResponseStreamResult") -> None:
        """合并另一个 result 的 usage 和 cost 数据（用于多轮场景）。

        total_cost_usd 和 usage 都是 SDK session 级累计值，
        多个 guidance round 之间只需要保留最新（最大）的值，不做加法累加。
        tool_calls 则按调用顺序去重合并，便于统计整轮执行的真实工具数。
        """
        if other.total_cost_usd is not None:
            if self.total_cost_usd is not None:
                self.total_cost_usd = max(self.total_cost_usd, other.total_cost_usd)
            else:
                self.total_cost_usd = other.total_cost_usd
        if other.usage:
            if self.usage is None:
                self.usage = {}
            for key, val in other.usage.items():
                if isinstance(val, (int, float)):
                    current = self.usage.get(key) or 0
                    self.usage[key] = max(current, val)
        if other.tool_calls:
            existing_ids = {
                tc.get("id")
                for tc in self.tool_calls
                if isinstance(tc, dict) and tc.get("id")
            }
            merged_prefix: list[Dict[str, Any]] = []
            for tc in other.tool_calls:
                if not isinstance(tc, dict):
                    merged_prefix.append(tc)
                    continue
                tool_id = tc.get("id")
                if tool_id and tool_id in existing_ids:
                    continue
                merged_prefix.append(tc)
                if tool_id:
                    existing_ids.add(tool_id)
            if merged_prefix:
                self.tool_calls = merged_prefix + self.tool_calls

    def __repr__(self) -> str:
        return (
            f"ResponseStreamResult(text_len={len(self.text)}, "
            f"tool_calls={len(self.tool_calls)}, "
            f"has_structured={self.structured_data is not None}, "
            f"is_error={self.is_error})"
        )


class BaseClaudeAgent(ABC):
    """
    Claude SDK Agent 基类

    提供公共功能：
    - 会话管理（LRU 缓存，带异步锁保护）
    - 持久会话支持（可选，用于多轮对话）
    - Hook 构建（PreToolUse/PostToolUse）
    - Options 构建
    - 异步执行流程
    - 结构化输出支持（通过 output_format 和 StructuredOutput 工具）
    - 公共响应流处理方法

    子类需要实现的抽象方法：
    - _get_mcp_servers(): 返回 MCP Server 配置字典（支持多个服务器）
    - _get_allowed_tools(): 返回允许的工具列表
    - _get_agent_type(): 返回 Agent 类型（用于日志）

    可选覆盖的方法：
    - _get_disallowed_tools(): 返回禁用的工具列表（默认禁用所有内置工具）
    - _get_output_schema(): 返回结构化输出的 JSON Schema（默认返回 None，不使用结构化输出）
    - _get_system_prompt(): 返回系统提示词（默认返回 self.system_prompt）

    注意事项：
    - 如果 _get_allowed_tools() 依赖延迟加载的配置，应在配置加载后调用 _rebuild_hooks()
    - 结构化输出通过 Claude SDK 的 StructuredOutput 工具实现，数据在 ToolUseBlock.input 中
    - 持久会话模式下，客户端会保持连接，支持多轮对话
    """

    # 子类可覆盖的属性
    max_sessions: int = 100
    tools_requiring_args: tuple = ()
    persistent_session: bool = False  # 是否使用持久会话模式

    def __init__(
        self,
        model: Optional[str] = None,
        system_prompt: str = "",
        max_turns: int = 300,
        enable_hooks: bool = True,
        cwd: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        logger=None,
        setting_sources: Optional[List[SettingSource]] = None,
        use_claude_code_preset: bool = False,
        persistent_session: bool = False,
        # 新增参数（SDK 0.1.x+）
        max_budget_usd: Optional[float] = None,
        fallback_model: Optional[str] = None,
        cli_path: Optional[str] = None,
        max_thinking_tokens: Optional[int] = None,
        # 沙箱配置
        sandbox_enabled: bool = True,
        sandbox_auto_allow_bash: bool = True,
        sandbox_allow_local_binding: bool = True,
        sandbox_excluded_commands: Optional[List[str]] = None,
        # 双模型交替运行配置
        alt_model: Optional[str] = None,
        alt_api_key: Optional[str] = None,
        alt_base_url: Optional[str] = None,
    ):
        """
        初始化 Claude SDK Agent

        Args:
            model: 模型名称（默认从环境变量 AI_MODEL 读取）
            system_prompt: 系统提示词
            max_turns: 最大对话轮数
            enable_hooks: 是否启用 Hook
            cwd: 工作目录
            api_key: API 密钥（可选）
            base_url: API 基础 URL（可选）
            logger: 日志记录器（可选）
            setting_sources: 要加载的配置源列表，可选值: "user", "project", "local"
                - None（默认）: 不加载任何 filesystem settings（SDK 隔离模式）
                - ["project"]: 加载 cwd/.claude/settings.json 和 CLAUDE.md
                - ["user", "project", "local"]: 加载所有配置源
            use_claude_code_preset: 是否使用 Claude Code 的预设 system prompt
                - True: 使用 {"type": "preset", "preset": "claude_code"} 并 append 自定义 prompt
                - False（默认）: 使用纯自定义 system_prompt
            persistent_session: 是否使用持久会话模式
                - True: 客户端保持连接，支持多轮对话（如 Brain）
                - False（默认）: 每次 execute 后关闭连接
            max_budget_usd: 最大预算（美元），超过后停止执行
            fallback_model: 回退模型，主模型失败时使用
            cli_path: 自定义 Claude Code CLI 路径
            max_thinking_tokens: 思考块最大 token 数
            sandbox_enabled: 是否启用沙箱模式（默认 True）
            sandbox_auto_allow_bash: 沙箱模式下自动允许 Bash 命令（默认 True）
            sandbox_allow_local_binding: 允许进程绑定本地端口（默认 True，用于开发服务器）
            sandbox_excluded_commands: 始终绕过沙箱的命令列表（如 ["docker"]）
            alt_model: 备选模型名称（用于双模型交替运行，Guidance Loop 每轮轮换）
            alt_api_key: 备选模型 API 密钥
            alt_base_url: 备选模型 API 基础 URL
        """
        self.model = model or os.getenv("AI_MODEL")
        self.system_prompt = system_prompt
        self.max_turns = max_turns
        self.enable_hooks = enable_hooks
        self.cwd = cwd or str(Path.cwd())
        self.api_key = api_key
        self.base_url = base_url
        self.logger = logger or _logger
        self.setting_sources = setting_sources
        self.use_claude_code_preset = use_claude_code_preset
        self.persistent_session = persistent_session
        # 新增属性
        self.max_budget_usd = max_budget_usd
        self.fallback_model = fallback_model
        self.cli_path = cli_path
        self.max_thinking_tokens = max_thinking_tokens
        # 沙箱配置
        self.sandbox_enabled = sandbox_enabled
        self.sandbox_auto_allow_bash = sandbox_auto_allow_bash
        self.sandbox_allow_local_binding = sandbox_allow_local_binding
        self.sandbox_excluded_commands = sandbox_excluded_commands or []

        # 会话管理（LRU 缓存）
        self._sessions: OrderedDict[str, str] = OrderedDict()
        # 异步锁保护会话操作
        self._session_lock = asyncio.Lock()

        # 持久会话模式的客户端
        self._persistent_client: Optional[ClaudeSDKClient] = None
        self._persistent_session_active = False
        self._turn_count = 0

        # 上一次 ResultMessage 的 input_tokens（最后一个 API turn 的真实上下文大小），
        # 用于 per-tool-call 上下文大小估算
        self._last_result_input_tokens: int = 0
        # 最近一次流式处理中已观测到的工具调用数。
        # 即使 query 被 timeout/cancel 打断，也可用于执行摘要统计。
        self._last_seen_tool_calls_count: int = 0
        # ResultMessage.usage["input_tokens"] 的累计值，用于差值计算
        self._cumulative_input_tokens: int = 0
        # ResultMessage.total_cost_usd 的累计值，用于 per-turn 增量日志
        self._cumulative_cost_usd: float = 0.0

        # Task 工具调用 ID → 子代理名称映射（跨 stream 调用保持，避免 compact 后丢失名字）
        self._subagent_task_ids: Dict[str, str] = {}

        # 结构化输出缓存
        self._last_structured_response: Optional[Dict[str, Any]] = None

        # 反思追踪器（用于 PostToolUse Hook 检测停滞）
        self._reflection_tracker = ReflectionTracker()

        # cli_path 存在只代表用自定义 CLI 二进制；是否让 CLI 管理模型路由由开关决定
        self._use_local_cli = (
            self.cli_path is not None
            and os.getenv("CLI_MODEL_ROUTING", "true").lower() in ("true", "1", "yes")
        )
        self._env_config = build_env_config(
            self.model, self.api_key, self.base_url,
            use_local_cli=self._use_local_cli,
        ) if self.model or self._use_local_cli else {}

        # 双模型交替运行：主模型 + 备选模型组成 slot 列表，
        # Guidance Loop 每轮自动 rotate，两个不同模型交替推理
        self._model_slots: list[ModelSlot] = [
            ModelSlot(model=self.model, api_key=self.api_key,
                      base_url=self.base_url, label="primary"),
        ]
        if alt_model:
            self._model_slots.append(
                ModelSlot(model=alt_model, api_key=alt_api_key,
                          base_url=alt_base_url, label="alt"),
            )
        self._active_slot_idx: int = 0

        # 构建 Hooks（延迟构建，因为子类的抽象方法可能依赖延迟初始化的属性）
        # 子类如果有延迟加载的配置，应在使用前调用 _rebuild_hooks()
        self._hooks = self._build_hooks() if enable_hooks else None

    def _rebuild_hooks(self) -> None:
        """
        重新构建 Hooks

        当子类的 _get_allowed_tools() 或 _get_disallowed_tools() 依赖延迟加载的配置时，
        应在配置加载完成后调用此方法更新 Hooks。
        """
        if self.enable_hooks:
            self._hooks = self._build_hooks()

    def _build_hooks(self) -> Dict[HookEvent, List[HookMatcher]]:
        """构建 Hooks 配置"""
        agent_type = self._get_agent_type()
        return {
            "PreToolUse": [
                HookMatcher(
                    hooks=[
                        create_pre_tool_use_hook(
                            tools_requiring_args=self.tools_requiring_args,
                            allowed_tools=self._get_allowed_tools(),
                            disallowed_tools=self._get_disallowed_tools(),
                            agent_name=agent_type,
                            reflection_tracker=self._reflection_tracker,
                        )
                    ]
                )
            ],
            "PostToolUse": [HookMatcher(
                hooks=[create_post_tool_use_hook(
                    agent_name=agent_type,
                    reflection_tracker=self._reflection_tracker,
                    skill_hints=self._load_skill_hints(),
                )],
            )],
            # 子代理停止 Hook：日志记录（上下文注入由 PostToolUse 处理）
            "SubagentStop": [HookMatcher(
                hooks=[create_subagent_stop_hook(
                    agent_name=agent_type,
                )],
            )],
        }

    async def _store_session(self, thread_id: str, session_id: str):
        """
        存储会话 ID（用于 SDK 原生 resume 功能）

        这是一个 thread_id -> session_id 的映射层，用于多线程/多租户场景。
        当调用 execute() 时，会自动从 _sessions 获取 session_id 并传递给 SDK 的 resume 参数。

        Args:
            thread_id: 线程/租户标识符
            session_id: SDK 返回的会话 ID（来自 ResultMessage.session_id）

        Note:
            使用 LRU 淘汰机制，最多保存 max_sessions 个会话。
            会话过多时会自动淘汰最久未使用的会话。
        """
        async with self._session_lock:
            if thread_id in self._sessions:
                del self._sessions[thread_id]

            while len(self._sessions) >= self.max_sessions:
                self._sessions.popitem(last=False)

            self._sessions[thread_id] = session_id

    @abstractmethod
    def _get_mcp_servers(self) -> Optional[Dict[str, Dict[str, Any]]]:
        """
        返回 MCP Server 配置字典

        Returns:
            MCP 服务器配置字典，格式为 {server_name: server_config}
            返回 None 或空字典表示不使用 MCP
        """
        pass

    @abstractmethod
    def _get_allowed_tools(self) -> List[str]:
        """返回允许的工具列表"""
        pass

    @abstractmethod
    def _get_agent_type(self) -> str:
        """返回 Agent 类型（用于日志）"""
        pass

    def _get_agents(self) -> Optional[Dict[str, Any]]:
        """返回内建子代理（Claude Code SDK agents）定义。

        说明：
        - 该能力对应 `ClaudeAgentOptions.agents`，配合内建 `Task` 工具使用。
        - 子类可覆盖返回形如 {"name": {"description": ..., "prompt": ..., "tools": [...], "model": "inherit"}} 的字典。
        - 默认返回 None 表示不启用内建子代理。
        """
        return None

    def _get_disallowed_tools(self) -> List[str]:
        """
        返回禁用的工具列表

        默认不禁用任何工具（沙箱模式下允许所有工具）。
        子类可以覆盖此方法来禁用特定工具。
        """
        return []

    def _log_subagent_mcp_visibility(self, subagent_name: str) -> None:
        """子代理启动时，打印它能看到的 MCP 服务器（基于 visibility 配置）。"""
        mcp_servers = self._get_mcp_servers() or {}
        visible = []
        hidden = []
        for srv_name, srv_cfg in mcp_servers.items():
            if not isinstance(srv_cfg, dict):
                continue
            vis = srv_cfg.get("visibility", "all")
            if vis == "all" or vis == "subagent" or vis == f"subagent:{subagent_name}":
                visible.append(f"{srv_name} (vis={vis})")
            else:
                hidden.append(f"{srv_name} (vis={vis})")
        if visible or hidden:
            log_system_event(
                f"[{self._get_agent_type()}] 子代理 '{subagent_name}' MCP 可见性",
                {"visible": visible, "hidden": hidden},
            )

    def _log_available_tools(self, msg: "SystemMessage") -> None:
        """从 init SystemMessage 中提取并记录工具和 MCP 服务器信息。"""
        data = msg.data if hasattr(msg, "data") else {}
        if not isinstance(data, dict):
            return

        tools = data.get("tools")
        if tools and isinstance(tools, list):
            # log_system_event(
            #     f"[{self._get_agent_type()}] 已加载工具列表 ({len(tools)} 个)",
            #     {"tools": sorted(tools)},
            # )
            mcp_tools = [t for t in tools if t.startswith("mcp__")]
            builtin_tools = [t for t in tools if not t.startswith("mcp__")]
            if mcp_tools:
                servers: Dict[str, List[str]] = {}
                for t in mcp_tools:
                    parts = t.split("__", 2)
                    server = parts[1] if len(parts) >= 3 else "unknown"
                    servers.setdefault(server, []).append(t)
                # log_system_event(
                #     f"[{self._get_agent_type()}] MCP 工具",
                #     {s: sorted(ts) for s, ts in servers.items()},
                # )
            # if builtin_tools:
            #     log_system_event(
            #         f"[{self._get_agent_type()}] 内置工具",
            #         {"tools": sorted(builtin_tools)},
            #     )

        mcp_servers = data.get("mcp_servers")
        if mcp_servers is not None:
            log_system_event(
                f"[{self._get_agent_type()}] init 阶段 MCP 服务器",
                {"mcp_servers": mcp_servers},
            )

    async def _log_mcp_status(self, client: "ClaudeSDKClient") -> None:
        """连接后通过 get_mcp_status() 列举所有已注册的 MCP 工具。

        get_mcp_status() 是 SDK 提供的 API，返回每个 MCP server
        的连接状态和工具列表，比 init SystemMessage 更完整。
        """
        try:
            status = await client.get_mcp_status()
            if not status:
                log_system_event(
                    f"[{self._get_agent_type()}] MCP 状态: 无数据",
                )
                return

            servers = status.get("mcpServers", [])
            if not servers:
                log_system_event(
                    f"[{self._get_agent_type()}] MCP 状态: 无 MCP 服务器",
                )
                return

            for srv in servers:
                name = srv.get("name", "unknown")
                srv_status = srv.get("status", "unknown")
                tools = srv.get("tools", [])
                tool_names = [t.get("name", "") for t in tools] if tools else []
                error = srv.get("error")
                info = {
                    "status": srv_status,
                    "tools": sorted(tool_names) if tool_names else "none",
                }
                if error:
                    info["error"] = error
                log_system_event(
                    f"[{self._get_agent_type()}] MCP [{name}] ({len(tool_names)} tools)",
                    info,
                )
        except Exception as e:
            log_system_event(
                f"[{self._get_agent_type()}] get_mcp_status() 失败: {e}",
                level=logging.DEBUG,
            )

    async def _log_server_info(self, client: "ClaudeSDKClient") -> None:
        """连接后通过 get_server_info() 获取 init 阶段的完整信息。

        init 数据在 connect() 阶段被 SDK 内部消费，不会出现在
        receive_response() 的消息流中。需要通过此 API 主动获取。
        """
        try:
            info = await client.get_server_info()
            if not info:
                return

            # 先打印完整 key 列表，帮助排查数据结构
            log_system_event(
                f"[{self._get_agent_type()}] server_info keys",
                {"keys": sorted(info.keys())},
            )

            tools = info.get("tools", [])
            mcp_servers = info.get("mcp_servers", info.get("mcpServers", []))
            skills = info.get("skills", [])
            agents = info.get("agents", [])
            model = info.get("model", "unknown")

            mcp_tools = [t for t in tools if isinstance(t, str) and t.startswith("mcp__")]
            builtin_tools = [t for t in tools if isinstance(t, str) and not t.startswith("mcp__")]

            log_system_event(
                f"[{self._get_agent_type()}] server_info",
                {
                    "model": model,
                    "builtin_tools": sorted(builtin_tools),
                    "mcp_tools": sorted(mcp_tools),
                    "mcp_servers": mcp_servers,
                    "skills": skills,
                    "agents": [a.get("name", a) if isinstance(a, dict) else a for a in agents] if agents else [],
                },
            )
        except Exception as e:
            log_system_event(
                f"[{self._get_agent_type()}] get_server_info() 失败: {e}",
                level=logging.DEBUG,
            )

    def _get_output_schema(self) -> Optional[Dict[str, Any]]:
        """
        返回结构化输出的 JSON Schema

        默认返回 None，不使用结构化输出。
        子类可以覆盖此方法返回 JSON Schema 来启用结构化输出。

        Returns:
            JSON Schema 字典，或 None 表示不使用结构化输出

        Example::

            def _get_output_schema(self) -> Optional[Dict[str, Any]]:
                return {
                    "type": "object",
                    "properties": {
                        "analysis": {"type": "string"},
                        "confidence": {"type": "number"}
                    },
                    "required": ["analysis", "confidence"]
                }
        """
        return None

    def _get_system_prompt(self) -> str:
        """
        返回系统提示词

        默认返回 self.system_prompt。
        子类可以覆盖此方法来动态生成系统提示词。
        """
        return self.system_prompt

    def _load_skill_hints(self) -> Optional[str]:
        """从 cwd/.claude/skills/ 加载 skill 名称+描述提示文本。

        仅在 setting_sources 包含 "project" 时生效（表示启用了项目级 skills）。
        """
        if not self.setting_sources or "project" not in self.setting_sources:
            return None
        from pathlib import Path

        skills_dir = str(Path(self.cwd) / ".claude" / "skills")
        return load_skill_hints(skills_dir)

    # ==================== 持久会话支持 ====================

    def _resolve_transcript_path(self, session_id: str) -> Optional[str]:
        """通过 session_id 推导 transcript 文件路径

        Claude CLI 将 transcript 存储在:
        ~/.claude/projects/{encoded_cwd}/{session_id}.jsonl

        其中 encoded_cwd 是 cwd 绝对路径的 / 替换为 - 后的结果。
        """
        home = Path.home()
        encoded_cwd = self.cwd.replace("/", "-")
        candidate = home / ".claude" / "projects" / encoded_cwd / f"{session_id}.jsonl"
        if candidate.exists():
            return str(candidate)
        return None

    async def _ensure_connected(self) -> None:
        """
        确保持久会话客户端已连接

        仅在 persistent_session=True 时使用。
        如果客户端不存在或会话不活跃，会断开旧连接并创建新连接。
        """
        if not self.persistent_session:
            raise RuntimeError(
                "持久会话模式未启用，请设置 persistent_session=True"
            )

        async with self._session_lock:
            if self._persistent_client is None or not self._persistent_session_active:
                # 先断开旧连接（防止资源泄漏）
                if self._persistent_client is not None:
                    try:
                        await self._persistent_client.disconnect()
                    except Exception as e:
                        log_system_event(
                            f"[{self._get_agent_type()}] 断开旧连接时出错",
                            {"error": str(e)},
                            level=logging.DEBUG,
                        )
                    self._persistent_client = None

                # 构建选项并创建新连接
                options = self._build_options()
                self._persistent_client = ClaudeSDKClient(options=options)
                await self._persistent_client.connect()
                self._persistent_session_active = True
                self._turn_count = 0
                log_system_event(f"[{self._get_agent_type()}] 持久会话已建立")

                # 列举所有已注册的 MCP 工具（用于排查工具加载情况）
                # await self._log_mcp_status(self._persistent_client)
                # 列举 init 阶段的完整信息（工具、skills、agents 等）
                await self._log_server_info(self._persistent_client)

    async def reset_persistent_session(self) -> None:
        """
        重置持久会话（断开连接并清除状态）

        当需要开始新的对话或切换上下文时调用。
        """
        async with self._session_lock:
            if self._persistent_client is not None:
                try:
                    await self._persistent_client.disconnect()
                except Exception as e:
                    log_system_event(
                        f"[{self._get_agent_type()}] 断开连接时出错",
                        {"error": str(e)},
                        level=logging.DEBUG,
                    )

            self._persistent_client = None
            self._persistent_session_active = False
            self._turn_count = 0
            self._last_structured_response = None
            self._reflection_tracker = ReflectionTracker()
            self._active_slot_idx = 0
            log_system_event(f"[{self._get_agent_type()}] 持久会话已重置")

    @property
    def _has_alt_model(self) -> bool:
        """是否配置了备选模型（双模型交替运行）"""
        return len(self._model_slots) > 1

    @property
    def _active_model_slot(self) -> ModelSlot:
        return self._model_slots[self._active_slot_idx]

    async def _rotate_model(self, session_id: str) -> None:
        """切换到下一个模型配置，通过 resume session 保持上下文连续。

        快速路径：如果两个 slot 的 api_key 和 base_url 相同（同一 provider），
        通过 SDK 控制协议 set_model() 热切换模型名，无需杀进程重连（~0ms）。

        慢速路径：api_key 或 base_url 不同（跨 provider），必须
        断开当前 client -> 切换 slot 索引 -> 用新模型配置 resume 同一个 session。
        两个模型共享同一个 session transcript，实现交替推理。

        新模型连接失败时自动回滚到旧模型重新连接，保证 _persistent_client 始终可用。
        回滚成功后静默降级（不抛异常），调用方继续用旧模型执行。
        """
        next_idx = (self._active_slot_idx + 1) % len(self._model_slots)
        prev_idx = self._active_slot_idx
        prev_env_config = self._env_config
        prev_slot = self._model_slots[prev_idx]
        next_slot = self._model_slots[next_idx]

        log_system_event(
            f"[{self._get_agent_type()}] 模型切换: "
            f"{prev_slot.label}({prev_slot.model}) -> {next_slot.label}({next_slot.model})",
            {"session_id": session_id},
        )

        # ── 快速路径：同 provider 热切换（只改模型名，不杀进程） ──
        same_provider = (
            (prev_slot.api_key or "") == (next_slot.api_key or "")
            and (prev_slot.base_url or "") == (next_slot.base_url or "")
        )
        if same_provider and self._persistent_client:
            try:
                await self._persistent_client.set_model(next_slot.model)
                self._active_slot_idx = next_idx
                # 同步 env_config 中的模型名（保持内部状态一致）
                self._env_config = build_env_config(
                    next_slot.model, next_slot.api_key, next_slot.base_url,
                    use_local_cli=self._use_local_cli,
                ) if next_slot.model or self._use_local_cli else {}
                log_system_event(
                    f"[{self._get_agent_type()}] 模型已热切换到 "
                    f"{next_slot.label}({next_slot.model})（同 provider，无需重连）",
                )
                return
            except Exception as e:
                log_system_event(
                    f"[{self._get_agent_type()}] set_model() 热切换失败，"
                    f"降级为完整重连: {e}",
                    level=logging.WARNING,
                )
                # 降级到下方的慢速路径

        # ── 慢速路径：跨 provider 完整重连 ──

        # 断开旧 client
        if self._persistent_client:
            try:
                await self._persistent_client.disconnect()
            except Exception as e:
                log_system_event(
                    f"[{self._get_agent_type()}] 模型切换: 断开旧 client 时出错",
                    {"error": str(e)},
                    level=logging.DEBUG,
                )
            self._persistent_client = None

        # 切换活跃模型索引和环境变量
        self._active_slot_idx = next_idx
        self._env_config = build_env_config(
            next_slot.model, next_slot.api_key, next_slot.base_url,
            use_local_cli=self._use_local_cli,
        ) if next_slot.model or self._use_local_cli else {}

        try:
            options = self._build_options(resume_session_id=session_id)
            self._persistent_client = ClaudeSDKClient(options=options)
            await self._persistent_client.connect()
        except Exception as exc:
            # 新模型连接失败，回滚到旧模型重新连接
            log_system_event(
                f"[{self._get_agent_type()}] 备选模型连接失败，回滚到 "
                f"{prev_slot.label}({prev_slot.model})",
                {"error": str(exc)},
                level=logging.WARNING,
            )
            self._active_slot_idx = prev_idx
            self._env_config = prev_env_config
            # 回滚连接：如果这里也失败，异常自然向上传播由 query() 外层处理
            options = self._build_options(resume_session_id=session_id)
            self._persistent_client = ClaudeSDKClient(options=options)
            await self._persistent_client.connect()
            return

        await self._log_mcp_status(self._persistent_client)

        log_system_event(
            f"[{self._get_agent_type()}] 模型已切换到 {next_slot.label}({next_slot.model})",
        )

    def _pre_compact_flush(self, result: "ResponseStreamResult") -> None:
        """compact 前的状态刷新钩子。

        子类可覆盖此方法，在 session compact 前将关键状态持久化到文件。
        默认不做任何操作。在续跑循环中 solved=false 触发 compact 时调用，
        确保 compact 后 agent 读 progress.md 能恢复最新状态。
        """

    def _launch_progress_compiler_on_compact(self) -> None:
        """compact 检测后异步启动 ProgressCompiler，与 CLI 摘要生成并行。

        status:"compacting" 在 CLI LLM 调用之前发出，我们有 5-30 秒的窗口。
        ProgressCompiler 在后台产出 compact_handoff.md，供 recovery hook 消费。

        防重入：连续 compact（keep-alive tick）不重复启动。
        静默失败：不影响主流程。
        """
        tracker = self._reflection_tracker
        if tracker._progress_compiler_task and not tracker._progress_compiler_task.done():
            return  # 已有 task 在运行，不重复启动

        try:
            from chying_agent.brain_agent.progress_compiler import run_progress_compiler
            from chying_agent.runtime.context import get_current_work_dir

            work_dir = get_current_work_dir()
            if not work_dir:
                return

            log_file_path = None
            try:
                from chying_agent.claude_sdk.reflection import get_current_log_file_path
                log_file_path = get_current_log_file_path()
            except Exception:
                pass

            tracker._progress_compiler_task = asyncio.create_task(
                run_progress_compiler(work_dir, log_file_path=log_file_path)
            )
            log_system_event(
                "[ProgressCompiler] 异步启动（compact 边界，与 CLI 摘要并行）",
                {"work_dir": str(work_dir)},
            )
        except Exception as e:
            log_system_event(
                f"[ProgressCompiler] 异步启动失败: {e}",
                level=logging.WARNING,
            )

    def _get_context_pct(self) -> float:
        """计算当前上下文占窗口大小的百分比。"""
        if self._last_result_input_tokens <= 0:
            return 0.0
        window = _get_context_window_size()
        if window <= 0:
            return 0.0
        return self._last_result_input_tokens / window * 100

    @property
    def turn_count(self) -> int:
        """当前会话的对话轮数"""
        return self._turn_count

    # ==================== 公共响应流处理 ====================

    async def _process_response_stream(
        self,
        client: ClaudeSDKClient,
        agent_type: Optional[str] = None,
    ) -> ResponseStreamResult:
        """
        处理 Claude SDK 响应流的公共方法

        从响应流中提取文本、工具调用、结构化输出等信息。
        支持 ToolResultBlock 在 UserMessage 和 AssistantMessage 中的两种情况。

        Args:
            client: ClaudeSDKClient 实例
            agent_type: Agent 类型名称（用于日志，默认使用 _get_agent_type()）

        Returns:
            ResponseStreamResult 包含所有提取的信息
        """
        agent_type = agent_type or self._get_agent_type()

        result = ResponseStreamResult()
        self._last_seen_tool_calls_count = 0
        tool_calls_map: Dict[str, Dict[str, Any]] = {}  # id -> {tool, input}
        warned_task_ids: set[str] = set()  # 已告警的子 agent，防止重复日志
        consecutive_api_errors = 0  # API 错误计数，防止死循环
        MAX_CONSECUTIVE_API_ERRORS = 3
        usage_tracker = _StreamUsageTracker(
            baseline_input_tokens=self._last_result_input_tokens,
        )

        # 消息间隔超时：如果连续 MESSAGE_GAP_TIMEOUT 秒没有收到新消息，判定为 hang
        MESSAGE_GAP_TIMEOUT = 600  # 10 分钟
        response_iter = client.receive_response().__aiter__()

        while True:
            try:
                msg = await asyncio.wait_for(response_iter.__anext__(), timeout=MESSAGE_GAP_TIMEOUT)
            except StopAsyncIteration:
                break
            except asyncio.TimeoutError:
                log_system_event(
                    f"[{agent_type}] ⚠️ 流式响应超时（{MESSAGE_GAP_TIMEOUT}s 无新消息），中断等待",
                    level=logging.WARNING,
                )
                result.is_error = True
                result.error_message = f"response_stream_timeout ({MESSAGE_GAP_TIMEOUT}s)"
                break
            except (asyncio.CancelledError, KeyboardInterrupt):
                # 外部 cancel（asyncio.timeout / 用户中断）到达时，
                # ResultMessage 未被接收，_cumulative_cost_usd 不会更新。
                # 用 stream tracker 或历史累计数据估算本轮 cost，
                # 避免 cancel 场景下 cost 丢失为 0。
                self._last_seen_tool_calls_count = len(result.tool_calls)
                if usage_tracker.has_data or self._cumulative_input_tokens > 0:
                    # 优先用 stream tracker 的实时数据；回退到历史累计 input_tokens
                    est_input = usage_tracker.latest_input_tokens or self._cumulative_input_tokens
                    est_output = usage_tracker.cumulative_output_tokens
                    estimated = _estimate_cost_from_tokens(est_input, est_output)
                    if estimated > self._cumulative_cost_usd:
                        self._cumulative_cost_usd = estimated
                        log_system_event(
                            f"[{agent_type}] cancel 时估算 cost: ${estimated:.2f}"
                            f" (input={est_input}"
                            f" output={est_output}"
                            f" turns={usage_tracker.api_turns})",
                            level=logging.WARNING,
                        )
                raise

            if isinstance(msg, AssistantMessage):
                # 判断消息来源：parent_tool_use_id 非空表示来自子代理
                parent_id = getattr(msg, "parent_tool_use_id", None)
                if parent_id and parent_id in self._subagent_task_ids:
                    source_label = format_tool_source_prefix(True, self._subagent_task_ids[parent_id])
                elif parent_id:
                    source_label = format_tool_source_prefix(True, "")
                else:
                    source_label = format_orchestrator_prefix(agent_type)

                # 检测 API 错误（SDK 将 API 层错误标记在 AssistantMessage.error 字段）
                if msg.error is not None:
                    consecutive_api_errors += 1
                    error_text = ""
                    for block in msg.content:
                        if isinstance(block, TextBlock):
                            error_text += block.text
                    log_system_event(
                        f"{source_label}❌ API 错误 ({consecutive_api_errors}/{MAX_CONSECUTIVE_API_ERRORS})",
                        {
                            "error_type": msg.error,
                            "detail": error_text,
                        },
                        level=logging.ERROR,
                    )
                    # 检测 transcript 损坏（模型幻觉产生的 phantom tool_use_id）
                    # 典型错误: "tool result's tool id(call_xxx) not found"
                    if "tool id" in error_text and "not found" in error_text:
                        log_system_event(
                            f"{source_label}⚠️ 检测到 transcript 中存在幻觉 tool_use_id，"
                            "标记为 transcript_corrupt",
                            level=logging.WARNING,
                        )
                        result.is_error = True
                        result.transcript_corrupt = True
                        result.error_message = f"transcript_corrupt: {error_text}"
                        break

                    if consecutive_api_errors >= MAX_CONSECUTIVE_API_ERRORS:
                        log_system_event(
                            f"{source_label}🛑 连续 API 错误达到上限，终止流处理",
                            {"error_type": msg.error, "last_detail": error_text},
                            level=logging.ERROR,
                        )
                        result.is_error = True
                        result.error_message = f"consecutive_api_errors ({msg.error}): {error_text}"
                        break
                    continue

                # 收到正常 AssistantMessage，重置 API 错误计数
                consecutive_api_errors = 0

                for block in msg.content:
                    if isinstance(block, TextBlock):
                        result.text += block.text
                        # 记录文本响应（完整内容）
                        if block.text.strip():
                            log_system_event(
                                f"{source_label}📝 文本响应",
                                {"text": block.text},
                            )
                            # Timeline 记录 Orchestrator 的文本输出（非子代理）
                            if not parent_id:
                                try:
                                    from .hooks import _get_timeline_path, _append_timeline
                                    from datetime import datetime as _dt
                                    _tl_path = _get_timeline_path()
                                    if _tl_path:
                                        _tl_now = _dt.now().strftime("%H:%M")
                                        _tl_text = block.text.strip()[:150]
                                        _append_timeline(_tl_path, f"{_tl_now} [分析] {_tl_text}")
                                except Exception:
                                    pass

                    elif isinstance(block, ThinkingBlock):
                        # 记录完整思考过程（不截断）
                        log_system_event(
                            f"{source_label}💭 思考过程",
                            {"thinking": block.thinking},
                        )

                    elif isinstance(block, ToolUseBlock):
                        # 检查是否是 StructuredOutput 工具
                        if block.name == "StructuredOutput":
                            if isinstance(block.input, dict):
                                result.structured_data = block.input
                                self._last_structured_response = block.input
                                # 记录完整结构化输出（不截断）
                                log_system_event(
                                    f"{source_label}📋 获取到结构化输出",
                                    {"data": block.input},
                                )
                        else:
                            # 记录子代理创建工具的 ID → 名称映射
                            # SDK 使用 "Task" 或 "Agent" 作为子代理创建工具名
                            if block.name in ("Task", "Agent") and isinstance(block.input, dict):
                                name = block.input.get("subagent_type") or block.input.get("description", "")
                                if name:
                                    self._subagent_task_ids[block.id] = name
                            # 记录工具调用（完整参数，不截断）
                            tool_calls_map[block.id] = {
                                "tool": block.name,
                                "input": block.input,
                                "id": block.id,
                            }
                            result.tool_calls.append(tool_calls_map[block.id])
                            self._last_seen_tool_calls_count = len(result.tool_calls)
                            # 工具显示名：Agent/Task 工具附带子代理类型（如 Agent:browser）
                            display_name = block.name
                            if block.name in ("Task", "Agent") and isinstance(block.input, dict):
                                sub_type = block.input.get("subagent_type") or block.input.get("description", "")
                                if sub_type:
                                    display_name = f"{block.name}:{sub_type}"
                            # 记录工具调用日志
                            log_tool_event(
                                f"🔧 {source_label}调用工具: {display_name}",
                                {"id": block.id, "input": block.input},
                            )
                            # 子代理启动时：展示该 subagent 可见的 MCP 服务器
                            if block.name in ("Task", "Agent") and isinstance(block.input, dict):
                                sub_type = block.input.get("subagent_type", "")
                                if sub_type:
                                    self._log_subagent_mcp_visibility(sub_type)

                    elif isinstance(block, ToolResultBlock):
                        # ToolResultBlock 可能在 AssistantMessage 中
                        tool_id = block.tool_use_id
                        if tool_id in tool_calls_map:
                            tc = tool_calls_map[tool_id]
                            tc["output"] = block.content
                            is_error = block.is_error or False
                            status = "❌" if is_error else "✅"
                            usage_inline = usage_tracker.format_inline()
                            in_sz = _format_data_size(tc.get("input"))
                            out_sz = _format_data_size(block.content)
                            size_info = f"in={in_sz} out={out_sz}"
                            log_tool_event(
                                f"{status} {source_label}工具完成: {tc['tool']}"
                                + f" | {size_info}"
                                + (f" | {usage_inline}" if usage_inline else ""),                                {
                                    "id": tool_id,
                                    "output": block.content,
                                    "is_error": is_error,
                                },
                            )

            elif isinstance(msg, UserMessage):
                # UserMessage 可能包含 ToolResultBlock（工具执行结果）
                # 判断消息来源
                parent_id = getattr(msg, "parent_tool_use_id", None)
                if parent_id and parent_id in self._subagent_task_ids:
                    um_source_label = format_tool_source_prefix(True, self._subagent_task_ids[parent_id])
                elif parent_id:
                    um_source_label = format_tool_source_prefix(True, "")
                else:
                    um_source_label = format_orchestrator_prefix(agent_type)

                if isinstance(msg.content, list):
                    for item in msg.content:
                        if isinstance(item, ToolResultBlock):
                            tool_id = item.tool_use_id
                            if tool_id in tool_calls_map:
                                tc = tool_calls_map[tool_id]
                                tc["output"] = item.content
                                is_error = item.is_error or False
                                status = "❌" if is_error else "✅"
                                usage_inline = usage_tracker.format_inline()
                                in_sz = _format_data_size(tc.get("input"))
                                out_sz = _format_data_size(item.content)
                                size_info = f"in={in_sz} out={out_sz}"
                                log_tool_event(
                                    f"{status} {um_source_label}工具完成: {tc['tool']}"
                                    + f" | {size_info}"
                                    + (f" | {usage_inline}" if usage_inline else ""),
                                    {
                                        "id": tool_id,
                                        "output": item.content,
                                        "is_error": is_error,
                                    },
                                )

            elif isinstance(msg, SystemMessage):
                # task_started: 使用专用格式化展示任务下发
                if msg.subtype == "task_started" and isinstance(msg.data, dict):
                    log_task_event(msg.data, agent_type)
                elif msg.subtype != 'init': 
                    # init 时显示的信息太多了，刷屏了，暂时不需要，后面有需要可以去除这个限制，看看 都加载了什么工具 subtype=init data={"type": "system", "subtype": "init", "cwd": "/Users/yhy/Documents/Github/CHYing-agent/agent-work", "session_id": "0309c802-c3b0-40ce-822a-4df7e02782e8", "tools": ["
                    # 其他系统消息使用通用格式
                    log_system_event(
                        f"[{agent_type}] 系统消息",
                        {"subtype": msg.subtype, "data": msg.data},
                    )
                self._log_available_tools(msg)

                # Compact 检测：CLI auto-compact 触发时发送 status="compacting" 的 SystemMessage。
                # 设置标志后，下一个 stream 的 PreToolUse hook 会拦截第一个写入型工具调用，
                # 要求 agent 先读取 attack_timeline.md 恢复上下文。
                if (
                    msg.subtype == "status"
                    and isinstance(msg.data, dict)
                    and msg.data.get("status") == "compacting"
                ):
                    self._reflection_tracker._compact_deny_remaining = 1  # 1 = in recovery mode
                    self._reflection_tracker._compact_confirmed_reads = set()  # 每次 compact 都清空
                    recovery_files = ", ".join(
                        f
                        for f in ("progress.md", "findings.log", "hint.md")
                        if f in _get_compact_recovery_files()
                    )
                    log_system_event(
                        f"[{agent_type}] Compact detected, entering recovery mode "
                        f"(must read: {recovery_files} before proceeding; "
                        "attack_timeline.md is now optional for provenance)",
                    )
                    # 异步启动 ProgressCompiler，与 CLI 的 LLM 摘要并行运行。
                    # status:"compacting" 在 CLI LLM 调用前发出，我们有 5-30s 并行窗口。
                    self._launch_progress_compiler_on_compact()

                # Compact 完成检测：compact_boundary 在 LLM 摘要完成后发出，
                # 标记新上下文的锚点。仅日志记录，用于赛后分析 compact 耗时。
                if msg.subtype == "compact_boundary" and isinstance(msg.data, dict):
                    _cb_meta = msg.data.get("compact_metadata", {})
                    _pc_task = self._reflection_tracker._progress_compiler_task
                    log_system_event(
                        f"[{agent_type}] Compact 完成",
                        {
                            "trigger": _cb_meta.get("trigger", "unknown"),
                            "pre_tokens": _cb_meta.get("pre_tokens", 0),
                            "progress_compiler_status": (
                                "done" if (_pc_task and _pc_task.done())
                                else "running" if _pc_task
                                else "not_started"
                            ),
                        },
                    )

                # 子 agent 超限监控（仅告警）
                # 实际 turns 限制由 SDK AgentDefinition.maxTurns 在 CLI 内部强制执行，
                # stop_task 对同步子代理无效，这里只做日志监控。
                if msg.subtype == "task_progress" and isinstance(msg.data, dict):
                    usage = msg.data.get("usage", {})
                    task_id = msg.data.get("task_id")
                    tool_uses = usage.get("tool_uses", 0)
                    duration_ms = usage.get("duration_ms", 0)

                    if (
                        task_id
                        and task_id not in warned_task_ids
                        and tool_uses > SUBAGENT_MAX_TOOL_USES
                    ):
                        agent_desc = msg.data.get("description", "")
                        log_system_event(
                            f"[{agent_type}] ⚠️ 子 agent 工具调用超过阈值（等待 SDK maxTurns 生效）",
                            {
                                "task_id": task_id,
                                "description": agent_desc,
                                "tool_uses": tool_uses,
                                "duration_ms": duration_ms,
                                "threshold": SUBAGENT_MAX_TOOL_USES,
                            },
                            level=logging.WARNING,
                        )
                        warned_task_ids.add(task_id)

            elif isinstance(msg, StreamEvent):
                # StreamEvent 用于流式消息更新（当 include_partial_messages=True 时）
                # 提取 session_id
                if msg.session_id and not result.session_id:
                    result.session_id = msg.session_id
                # 从原始 Anthropic API 事件中提取实时 token 用量
                usage_tracker.process_event(msg.event)

            elif isinstance(msg, ResultMessage):
                result.session_id = msg.session_id
                result.usage = msg.usage
                result.total_cost_usd = msg.total_cost_usd

                # 更新 baseline input_tokens 供下一轮 query 的 tracker 使用
                # 优先使用 stream tracker 的 latest_input_tokens（最后一个 API turn 的真实上下文大小）
                if usage_tracker.latest_input_tokens > 0:
                    self._last_result_input_tokens = usage_tracker.latest_input_tokens
                elif msg.usage:
                    # 回退：stream event 不可用时，用 ResultMessage 累计值的差值估算本次 query 的上下文
                    new_cumulative = msg.usage.get("input_tokens", 0)
                    if new_cumulative > 0 and self._cumulative_input_tokens > 0:
                        # 差值 = 本次 query 消耗的 input tokens（近似最后一个 turn 的上下文大小）
                        delta = new_cumulative - self._cumulative_input_tokens
                        if delta > 0:
                            self._last_result_input_tokens = delta
                    elif new_cumulative > 0:
                        # 首次 query，无法差值计算，用累计值（此时累计值就是单次值）
                        self._last_result_input_tokens = new_cumulative
                # 保存 prev 值用于 per-turn 增量日志（在 _log_usage_summary 之前）
                prev_input_tokens_snapshot = self._cumulative_input_tokens
                prev_cost_usd_snapshot = self._cumulative_cost_usd
                # 更新累计值记录
                if msg.usage:
                    self._cumulative_input_tokens = msg.usage.get("input_tokens", 0)

                if msg.is_error:
                    result.is_error = True
                    result.error_message = msg.result or "未知错误"
                    # 判断是否因 max_turns 耗尽：num_turns >= max_turns
                    # 这不是致命错误，Guidance Loop 可以继续下一轮
                    if hasattr(msg, 'num_turns') and msg.num_turns >= self.max_turns:
                        result.max_turns_exhausted = True
                        log_system_event(
                            f"[{agent_type}] max_turns ({self.max_turns}) 耗尽，"
                            f"Guidance Loop 将继续下一轮",
                            {"num_turns": msg.num_turns},
                        )
                else:
                    # 优先使用 structured_output 字段（新版 SDK）
                    if hasattr(msg, 'structured_output') and msg.structured_output is not None:
                        result.structured_data = msg.structured_output
                        self._last_structured_response = msg.structured_output
                        log_system_event(
                            f"[{agent_type}] 获取到结构化输出（通过 ResultMessage.structured_output）",
                            {"keys": list(msg.structured_output.keys()) if isinstance(msg.structured_output, dict) else "N/A"},
                        )
                    # 回退：尝试从 ResultMessage.result 解析结构化输出
                    elif msg.result and result.structured_data is None:
                        try:
                            structured_result = json.loads(msg.result)
                            if isinstance(structured_result, dict):
                                result.structured_data = structured_result
                                self._last_structured_response = structured_result
                                log_system_event(
                                    f"[{agent_type}] 获取到结构化输出（通过 ResultMessage.result）",
                                    {"keys": list(structured_result.keys())},
                                )
                        except json.JSONDecodeError:
                            pass

                log_system_event(
                    f"[{agent_type}] ✨ 完成",
                    {
                        "turn": self._turn_count,
                        "tools_used": len(result.tool_calls),
                        "api_turns": usage_tracker.api_turns,
                        "cost_usd": msg.total_cost_usd,
                        "is_error": msg.is_error,
                        "stream_token_tracking": usage_tracker.has_data,
                    },
                )
                # 上下文大小：优先 stream 的实时数据，回退到差值估算
                ctx_tokens = usage_tracker.latest_input_tokens or self._last_result_input_tokens
                _log_usage_summary(
                    agent_type, msg.usage, msg.total_cost_usd, ctx_tokens,
                    prev_input_tokens=prev_input_tokens_snapshot,
                    prev_cost_usd=prev_cost_usd_snapshot,
                )
                # 更新 cumulative cost 记录
                if msg.total_cost_usd is not None:
                    self._cumulative_cost_usd = msg.total_cost_usd
                break

        # 通过 session_id 推导 transcript_path（持久会话模式下 Hook 无法捕获）
        if result.session_id and not result.transcript_path:
            result.transcript_path = self._resolve_transcript_path(result.session_id)

        self._last_seen_tool_calls_count = len(result.tool_calls)
        return result

    # ==================== 持久会话执行方法 ====================

    def _build_guidance_query(
        self, result: ResponseStreamResult, round_count: int
    ) -> tuple[str, bool, str]:
        """分析本轮结果，构建下一轮指导性 query。

        读取 agent 的结构化输出和 progress.md Dead Ends，判断 agent 状态，
        决定下一轮的指导方向。

        Returns:
            (guidance_message, is_exhausted, guidance_type):
            - guidance_message: 追加给 agent 的指导 query
            - is_exhausted: True 表示多轮无突破，应终止会话
            - guidance_type: 分支类型 (continue/pivot/blocked/exhausted)
        """
        structured = result.structured_data or {}
        summary = structured.get("summary", "")
        blocked_reason = structured.get("blocked_reason", "")
        next_steps = structured.get("next_steps", [])
        confidence = structured.get("confidence", 0.5)

        work_dir_str = get_current_work_dir_str()

        dead_ends: list[str] = []
        if work_dir_str:
            from pathlib import Path
            try:
                dead_ends = extract_dead_ends(Path(work_dir_str))
            except Exception:
                pass

        is_repeating = self._is_repeating_summary(summary)

        if is_repeating and round_count >= 3:
            return ("", True, "exhausted")

        if is_repeating or confidence < 0.2:
            self._reflection_tracker._abandon_active = True
            dead_end_text = "\n".join(f"- {d}" for d in dead_ends) if dead_ends else "(none recorded)"
            pivot_msg = (
                "你上一轮的进展有限。以下方向已确认无效，系统已禁止重试:\n"
                f"{dead_end_text}\n\n"
                "请从完全不同的角度重新审视目标。"
                "优先探索你之前未尝试过的方向。"
                "重新阅读 progress.md 中的 Attack Tree 和 findings.log，"
                "寻找可以组合的发现或未深入的线索。"
                "只有在确认找到 FLAG 后才输出 solved=true 的结构化结果。"
            )
            # 控制平面注入（pivot 分支）
            cp_summary = self._reflection_tracker.get_control_plane_summary()
            if cp_summary:
                pivot_msg += f"\n\n{cp_summary}"
            anomaly_text = self._reflection_tracker.get_unconsumed_anomalies()
            if anomaly_text:
                pivot_msg += f"\n\n{anomaly_text}"
            return (pivot_msg, False, "pivot")

        if blocked_reason:
            return (
                f"你报告了阻塞原因: {blocked_reason}。"
                "请绕过此阻塞或尝试其他方向。继续执行。"
                "只有在确认找到 FLAG 后才输出 solved=true 的结构化结果。",
                False,
                "blocked",
            )

        parts = ["继续执行。"]

        # §2.2 unconsumed anomaly 前置注入（confirmed/tested 发现提醒优先于其他指导）
        # 置于 parts 开头，确保 LLM 在本轮开始时第一眼看到未利用的高价值线索
        anomaly_text = self._reflection_tracker.get_unconsumed_anomalies()
        if anomaly_text:
            parts.insert(0, anomaly_text)

        if next_steps:
            steps_text = "; ".join(next_steps[:3])
            parts.append(f"你计划的下一步: {steps_text} -- 按此计划推进。")

        if confidence < 0.5:
            parts.append(
                "当前信心偏低，请重新审视已有发现（findings.log / progress.md Attack Tree），"
                "看是否有可以组合的线索。"
            )

        parts.append(
            "特别注意 progress.md 的 Dead Ends 段落，不要重复已失败的方法。"
            "只有在确认找到 FLAG 后才输出 solved=true 的结构化结果。"
        )

        # §3.3 guidance query 模板优化
        parts.append(
            "\n在继续之前，请回答：\n"
            "1. 到目前为止最关键的发现是什么？（如果没有 record_key_finding 过，先补记）\n"
            "2. 是否存在题目提供但你还没分析的资源（附件、下载链接、提示）？\n"
            "3. 当前方向的信息增益是否在下降？如果是，换方向。"
        )

        # §2.1 控制平面状态注入
        cp_summary = self._reflection_tracker.get_control_plane_summary()
        if cp_summary:
            parts.append(cp_summary)

        # anomaly 已在 parts[0] 前置注入，不再重复追加

        # §1.4 子代理 stop_reason 检查
        stop_reason = self._reflection_tracker.get_last_subagent_stop_reason()
        if stop_reason and stop_reason in ("max_turns", "blocked"):
            parts.append(
                f"⚠️ 子代理因 {stop_reason} 退出，其工作可能未完成。"
                "请决定是继续同方向还是换方向。"
            )

        return (" ".join(parts), False, "continue")

    def _is_repeating_summary(self, summary: str) -> bool:
        """检测当前 summary 是否与上一轮重复（说明 agent 在绕圈）。"""
        if not hasattr(self, "_last_summaries"):
            self._last_summaries: list[str] = []

        if not summary:
            return False

        normalized = summary.strip().lower()[:200]

        is_repeat = False
        for prev in self._last_summaries[-3:]:
            if not prev:
                continue
            overlap = sum(1 for a, b in zip(normalized, prev) if a == b)
            similarity = overlap / max(len(normalized), len(prev), 1)
            if similarity > 0.6:
                is_repeat = True
                break

        self._last_summaries.append(normalized)
        if len(self._last_summaries) > 5:
            self._last_summaries = self._last_summaries[-5:]

        return is_repeat

    def _emit_session_metrics(self) -> None:
        """会话结束时写入控制平面指标到 dumps/session_metrics.json。"""
        try:
            from chying_agent.runtime.context import get_current_work_dir
            work_dir = get_current_work_dir()
            if not work_dir or not self._reflection_tracker:
                return

            metrics = self._reflection_tracker.get_session_metrics()

            dumps_dir = work_dir / "dumps"
            dumps_dir.mkdir(parents=True, exist_ok=True)
            metrics_file = dumps_dir / "session_metrics.json"

            import json
            from datetime import datetime
            metrics["timestamp"] = datetime.now().isoformat()
            metrics["agent_type"] = self._get_agent_type()

            # 追加写入（多轮 session 的指标累积）
            existing = []
            if metrics_file.exists():
                try:
                    existing = json.loads(metrics_file.read_text(encoding="utf-8"))
                    if not isinstance(existing, list):
                        existing = [existing]
                except Exception:
                    existing = []
            existing.append(metrics)
            metrics_file.write_text(
                json.dumps(existing, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            log_system_event(
                f"[{self._get_agent_type()}] Session metrics written",
                {"path": str(metrics_file)},
            )
        except Exception as e:
            log_system_event(
                f"[{self._get_agent_type()}] Failed to write session metrics",
                {"error": str(e)},
                level=logging.WARNING,
            )

    async def query(self, message: str) -> ResponseStreamResult:
        """在持久会话中发送查询并运行 Guidance Loop。

        Guidance Loop: 每轮 agent 跑 max_turns 次工具调用后自然停下，
        系统分析结构化输出，追加指导性 query 继续。不主动 compact，
        不 interrupt，上下文完整保留。

        最多 MAX_GUIDANCE_ROUNDS 轮（每轮 max_turns 次工具调用）。
        """
        if not self.persistent_session:
            raise RuntimeError(
                "query() 仅在持久会话模式下可用，请设置 persistent_session=True "
                "或使用 execute() 方法"
            )

        await self._ensure_connected()

        STREAM_TIMEOUT_MAX_RETRIES = 1

        try:
            await self._persistent_client.query(message)
            self._turn_count += 1

            result = await self._process_response_stream(self._persistent_client)
            result.turn_count = self._turn_count

            # 流式超时重试
            retry_count = 0
            while (
                result.is_error
                and result.error_message
                and "response_stream_timeout" in result.error_message
                and retry_count < STREAM_TIMEOUT_MAX_RETRIES
            ):
                retry_count += 1
                log_system_event(
                    f"[{self._get_agent_type()}] 流式超时重试 {retry_count}/{STREAM_TIMEOUT_MAX_RETRIES}",
                    level=logging.WARNING,
                )
                try:
                    await self._persistent_client.query(
                        "你的上一次响应似乎中断了，请继续执行。"
                    )
                    self._turn_count += 1
                    new_result = await self._process_response_stream(
                        self._persistent_client
                    )
                    new_result.turn_count = self._turn_count
                    new_result.accumulate_usage(result)
                    result = new_result
                except Exception as e:
                    log_system_event(
                        f"[{self._get_agent_type()}] 流式超时重试失败",
                        {"error": str(e), "retry": retry_count},
                        level=logging.WARNING,
                    )
                    break

            # Guidance Loop: 分段跑 + 追加 query 指导
            agent_type = self._get_agent_type()
            round_count = 0

            while (
                (not result.is_error or result.max_turns_exhausted)
                and not _is_solved(result)
                and round_count < MAX_GUIDANCE_ROUNDS
            ):
                round_count += 1

                # 重置 max_turns_exhausted 标志（下一轮重新判断）
                result.is_error = False
                result.max_turns_exhausted = False

                self._pre_compact_flush(result)

                guidance_msg, is_exhausted, guidance_type = self._build_guidance_query(
                    result, round_count
                )

                if is_exhausted:
                    log_guidance_event(
                        round_count, MAX_GUIDANCE_ROUNDS, "exhausted",
                    )
                    result.session_exhausted = True
                    break

                log_guidance_event(
                    round_count, MAX_GUIDANCE_ROUNDS, guidance_type,
                    guidance_len=len(guidance_msg),
                )

                # 双模型交替：在发送 guidance query 前切换到另一个模型
                rotated = False
                if self._has_alt_model and result.session_id:
                    try:
                        await self._rotate_model(result.session_id)
                        rotated = True
                    except Exception as e:
                        log_system_event(
                            f"[{agent_type}] 模型切换失败，继续使用当前模型: "
                            f"{self._active_model_slot.label}({self._active_model_slot.model})",
                            {"error": str(e)},
                            level=logging.WARNING,
                        )

                prev_result = result
                await self._persistent_client.query(guidance_msg)
                self._turn_count += 1
                result = await self._process_response_stream(
                    self._persistent_client
                )
                result.turn_count = self._turn_count
                result.accumulate_usage(prev_result)

                # ── Transcript 损坏恢复 ──
                # 场景：前一模型（如 glm-5.1）幻觉出 phantom tool_use_id，
                # 切换后的新模型 400 "tool result's tool id not found"。
                # 处理：回滚到原模型，用原模型重新发送本轮 guidance_msg。
                if result.transcript_corrupt and rotated:
                    log_system_event(
                        f"[{agent_type}] transcript 不兼容新模型，"
                        "回滚原模型并重发本轮 guidance",
                        level=logging.WARNING,
                    )
                    try:
                        sid = result.session_id or prev_result.session_id
                        if sid:
                            await self._rotate_model(sid)
                        # 用原模型重新发送同一条 guidance query
                        await self._persistent_client.query(guidance_msg)
                        self._turn_count += 1
                        result = await self._process_response_stream(
                            self._persistent_client
                        )
                        result.turn_count = self._turn_count
                        result.accumulate_usage(prev_result)
                    except Exception as e:
                        log_system_event(
                            f"[{agent_type}] 回滚原模型重发失败: {e}",
                            level=logging.ERROR,
                        )
                        break
                elif result.transcript_corrupt:
                    # 非轮换场景的 transcript 损坏，无法恢复
                    break

                # 上下文压缩已统一由 CLI 内置的 auto compact 处理
                # 通过 CLAUDE_CODE_AUTO_COMPACT_WINDOW 和 CLAUDE_AUTOCOMPACT_PCT_OVERRIDE 环境变量控制

            # Phase 3: 会话结束时写入控制平面指标
            self._emit_session_metrics()

            return result

        except Exception as e:
            log_system_event(
                f"[{self._get_agent_type()}] 查询异常，重置会话",
                {"error": str(e)},
                level=logging.WARNING,
            )
            await self.reset_persistent_session()
            return ResponseStreamResult(
                is_error=True,
                error_message=str(e),
            )

    async def follow_up(self, question: str) -> ResponseStreamResult:
        """
        追问（在持久会话中继续对话）

        Args:
            question: 追问内容

        Returns:
            ResponseStreamResult 包含响应信息
        """
        if not self._persistent_session_active:
            return ResponseStreamResult(
                is_error=True,
                error_message="没有活跃的会话，请先调用 query()",
            )

        return await self.query(question)

    # ==================== 属性 ====================
    # turn_count property 已在上方定义（第 624-627 行）

    @property
    def is_session_active(self) -> bool:
        """持久会话是否活跃"""
        return self._persistent_session_active

    @property
    def last_structured_response(self) -> Optional[Dict[str, Any]]:
        """最后一次结构化响应"""
        return self._last_structured_response

    @property
    def last_seen_tool_calls_count(self) -> int:
        """最近一次流式处理中已观测到的工具调用数。"""
        return self._last_seen_tool_calls_count

    # ==================== async with 支持 ====================

    async def __aenter__(self):
        """支持 async with 语法"""
        if self.persistent_session:
            await self._ensure_connected()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """退出时断开持久连接"""
        if self.persistent_session:
            await self.reset_persistent_session()

    def _build_options(
        self,
        context: Optional[Dict[str, Any]] = None,
        resume_session_id: Optional[str] = None,
        fork_session: bool = False,
    ) -> ClaudeAgentOptions:
        """
        构建 ClaudeAgentOptions

        Args:
            context: 额外上下文（会添加到 system_prompt）
            resume_session_id: 要恢复的会话 ID（使用 SDK 原生 resume 参数）
            fork_session: 恢复时是否 fork 到新会话（而非继续原会话）

        Returns:
            ClaudeAgentOptions 实例
        """
        # 构建 system_prompt
        base_prompt = self.system_prompt
        if context:
            context_str = json.dumps(context, ensure_ascii=False, indent=2)
            base_prompt = (
                f"{self.system_prompt}\n\n## 当前上下文\n```json\n{context_str}\n```"
            )

        # 根据 use_claude_code_preset 决定 tools 格式
        # system_prompt 始终为纯自定义字符串（替换 CLI 默认 prompt）
        # use_claude_code_preset 仅控制是否启用 Claude Code 内置工具集
        if self.use_claude_code_preset:
            # system_prompt_config = base_prompt
            system_prompt_config : Any = {
                 "type": "preset",
                "preset": "claude_code",
                "append": base_prompt,
            }
            # 启用 Claude Code 内置工具集（Read/Write/Edit/Bash/Glob/Grep/Task 等）
            tools_config: Any = {
                "type": "preset",
                "preset": "claude_code",
            }
        else:
            # 纯自定义 system_prompt，不使用预设工具集
            system_prompt_config = base_prompt
            tools_config = None

        slot = self._model_slots[self._active_slot_idx]
        env = build_env_config(
            slot.model, slot.api_key, slot.base_url,
            use_local_cli=self._use_local_cli,
        )

        # 构建 MCP servers 配置
        mcp_servers = self._get_mcp_servers()

        # 构建基础选项
        options_kwargs: Dict[str, Any] = {
            "tools": tools_config,  # Claude Code 预设工具集 或 None
            "system_prompt": system_prompt_config,
            "allowed_tools": self._get_allowed_tools(),
            "disallowed_tools": self._get_disallowed_tools(),
            "max_turns": self.max_turns,
            "cwd": self.cwd,
            "hooks": self._hooks,
            # 自动化 Agent 框架：跳过 CLI 权限提示，所有工具（含外部 MCP）自动允许
            "permission_mode": "bypassPermissions",
            # ⭐ SDK 原生会话管理参数
            # resume 和 continue_conversation 是互斥语义：
            # - resume="session-id" → CLI 收到 --resume <id>，精确恢复指定会话
            # - continue_conversation=True → CLI 收到 --continue，恢复"最近一次"对话
            # 两者同时设置时，--continue 可能覆盖 --resume 的行为（CLI 按最近会话匹配），
            # 在多题目并发（共享 cwd）场景下会恢复到错误的会话（串题）。
            # 因此：有明确 session_id 时只用 resume，不设 continue_conversation。
            "resume": resume_session_id,  # 要恢复的会话 ID
            "continue_conversation": False,  # 由 resume 精确指定会话，不使用 --continue
            "fork_session": fork_session,  # 恢复时是否 fork 到新会话
            "include_partial_messages": True,  # 启用部分消息流，以便尽早获取 session_id
        }

        # 本地 CLI 模式：不传 model（CLI 内部管理模型路由）
        # 远程 API 模式：使用 haiku 别名，通过环境变量映射到实际模型
        if not self._use_local_cli:
            options_kwargs["model"] = "haiku"

        # 只有当 env 有内容时才添加（避免干扰本地 Claude 配置）
        if env:
            options_kwargs["env"] = env

        # 添加 setting_sources（如果配置了）
        if self.setting_sources is not None:
            options_kwargs["setting_sources"] = self.setting_sources

        # 只有当 mcp_servers 不为空时才添加
        if mcp_servers:
            options_kwargs["mcp_servers"] = mcp_servers

        # 内建子代理（Task/agents）
        agents = self._get_agents()
        if agents:
            options_kwargs["agents"] = agents

        # 添加结构化输出配置
        output_schema = self._get_output_schema()
        if output_schema:
            options_kwargs["output_format"] = {
                "type": "json_schema",
                "schema": output_schema,
            }

        # 添加新版 SDK 参数（如果配置了）
        if self.max_budget_usd is not None:
            options_kwargs["max_budget_usd"] = self.max_budget_usd
        if self.fallback_model is not None:
            options_kwargs["fallback_model"] = self.fallback_model
        if self.cli_path is not None:
            options_kwargs["cli_path"] = self.cli_path
        if self.max_thinking_tokens is not None:
            options_kwargs["max_thinking_tokens"] = self.max_thinking_tokens

        # 添加沙箱配置
        if self.sandbox_enabled:
            sandbox_config: Dict[str, Any] = {
                "enabled": True,
                "autoAllowBashIfSandboxed": self.sandbox_auto_allow_bash,
            }
            # 网络配置
            if self.sandbox_allow_local_binding:
                sandbox_config["network"] = {
                    "allowLocalBinding": True,
                }
            # 排除命令列表
            if self.sandbox_excluded_commands:
                sandbox_config["excludedCommands"] = self.sandbox_excluded_commands
            options_kwargs["sandbox"] = sandbox_config

        return ClaudeAgentOptions(**options_kwargs)

    async def _run_oneshot(
        self,
        message: str,
        thread_id: str,
        context: Optional[Dict[str, Any]],
        on_session_start: Optional[
            Callable[[str, Optional[str]], Awaitable[None]]
        ],
        fork_session: bool,
    ) -> ResponseStreamResult:
        """One-shot 执行公共流程：构建 options -> 创建 client -> query -> 处理响应流 -> 会话回调/存储。

        调用方负责 try/except 和结果转换。内部异常直接向上抛出。
        """
        resume_session_id = self._sessions.get(thread_id)
        options = self._build_options(context, resume_session_id, fork_session)

        async with ClaudeSDKClient(options=options) as client:
            await client.query(message)
            result = await self._process_response_stream(client)

            if on_session_start and result.session_id:
                try:
                    await on_session_start(result.session_id, result.transcript_path)
                except Exception as e:
                    log_system_event(
                        f"[{self._get_agent_type()}] on_session_start 回调失败",
                        {"error": str(e)},
                        level=logging.WARNING,
                    )

            if result.session_id:
                await self._store_session(thread_id, result.session_id)

            return result

    async def execute(
        self,
        message: str,
        thread_id: str = "default",
        context: Optional[Dict[str, Any]] = None,
        on_session_start: Optional[
            Callable[[str, Optional[str]], Awaitable[None]]
        ] = None,
        fork_session: bool = False,
    ) -> Dict[str, Any]:
        """
        一次性执行 Agent 任务

        Args:
            message: 用户消息
            thread_id: 线程标识符（用于多线程/多租户会话管理）
            context: 额外上下文（会添加到 system_prompt）
            on_session_start: 当获取到 session_id 和 transcript_path 时的回调函数
                             签名: async def callback(session_id: str, transcript_path: Optional[str])
            fork_session: 恢复会话时是否 fork 到新会话（而非继续原会话）

        Returns:
            执行结果字典，包含：
            - success: 是否成功
            - response: 响应文本
            - tool_calls: 工具调用列表
            - session_id: 会话 ID（可用于后续 resume）
            - transcript_path: JSONL 文件路径
            - usage: 使用量统计
            - total_cost_usd: 总费用（美元）
            - error: 错误信息（如果失败）
        """
        log_system_event(
            f"[{self._get_agent_type()}] 开始执行",
            {
                "thread_id": thread_id,
                "message_preview": message
                if len(message) > 100
                else message,
            },
        )

        try:
            result = await self._run_oneshot(
                message, thread_id, context, on_session_start, fork_session
            )

            if result.is_error:
                return {
                    "success": False,
                    "response": result.error_message or "未知错误",
                    "tool_calls": result.tool_calls,
                    "error": "execution_error",
                    "session_id": result.session_id,
                    "transcript_path": result.transcript_path,
                }

            log_system_event(
                f"[{self._get_agent_type()}] 执行完成",
                {
                    "response_length": len(result.text),
                    "tool_calls_count": len(result.tool_calls),
                },
            )

            return {
                "success": True,
                "response": result.text,
                "tool_calls": result.tool_calls,
                "session_id": result.session_id,
                "transcript_path": result.transcript_path,
                "usage": result.usage,
                "total_cost_usd": result.total_cost_usd,
            }

        except Exception as e:
            log_system_event(
                f"[{self._get_agent_type()}] 执行异常",
                {"error": str(e)},
                level=logging.ERROR,
            )
            return {
                "success": False,
                "response": f"执行异常: {str(e)}",
                "tool_calls": [],
                "error": str(e),
                "transcript_path": None,
            }

    async def execute_structured(
        self,
        message: str,
        thread_id: str = "default",
        context: Optional[Dict[str, Any]] = None,
        on_session_start: Optional[
            Callable[[str, Optional[str]], Awaitable[None]]
        ] = None,
        fork_session: bool = False,
    ) -> StructuredOutput[Dict[str, Any]]:
        """
        一次性执行 Agent 任务并返回结构化输出

        结构化数据通过 SDK 的 StructuredOutput 工具 / ResultMessage / raw text 回退解析获取。

        Args:
            message: 用户消息
            thread_id: 线程标识符（用于多线程/多租户会话管理）
            context: 额外上下文（会添加到 system_prompt）
            on_session_start: 当获取到 session_id 和 transcript_path 时的回调函数
                             签名: async def callback(session_id: str, transcript_path: Optional[str])
            fork_session: 恢复会话时是否 fork 到新会话

        Returns:
            StructuredOutput 对象，包含：
            - data: 结构化数据（符合 schema 的字典）
            - raw_text: 原始文本响应（思考过程等）
            - tool_calls: 工具调用列表

        Raises:
            ValueError: 如果子类没有实现 _get_output_schema()
        """
        output_schema = self._get_output_schema()
        if output_schema is None:
            raise ValueError(
                f"{self.__class__.__name__} 没有实现 _get_output_schema() 方法，"
                "无法使用结构化输出。请覆盖该方法返回 JSON Schema。"
            )

        log_system_event(
            f"[{self._get_agent_type()}] 开始执行（结构化输出）",
            {
                "thread_id": thread_id,
                "message_preview": message,
            },
        )

        try:
            result = await self._run_oneshot(
                message, thread_id, context, on_session_start, fork_session
            )

            if result.is_error:
                return StructuredOutput(
                    data=None,
                    raw_text=result.error_message or "未知错误",
                    tool_calls=result.tool_calls,
                )

            # _process_response_stream 已通过多路回退提取结构化数据：
            # 1. ToolUseBlock(name="StructuredOutput")
            # 2. ResultMessage.structured_output
            # 3. ResultMessage.result JSON 解析
            structured_data = result.structured_data

            # 最终回退：raw text JSON 解析（处理不走 SDK 结构化路径的情况）
            if structured_data is None:
                candidate = (result.text or "").strip()
                if candidate.startswith("```"):
                    start = candidate.find("{")
                    end = candidate.rfind("}")
                    if start != -1 and end != -1 and end > start:
                        candidate = candidate[start : end + 1].strip()
                if candidate.startswith("{") and candidate.endswith("}"):
                    try:
                        structured_data = cast(Dict[str, Any], json.loads(candidate))
                        log_system_event(
                            f"[{self._get_agent_type()}] 结构化输出回退解析成功",
                            {"keys": list(structured_data.keys())},
                        )
                    except Exception:
                        pass

            log_system_event(
                f"[{self._get_agent_type()}] 执行完成（结构化输出）",
                {
                    "has_structured_data": structured_data is not None,
                    "response_length": len(result.text),
                    "tool_calls_count": len(result.tool_calls),
                },
            )

            return StructuredOutput(
                data=structured_data,
                raw_text=result.text,
                tool_calls=result.tool_calls,
            )

        except Exception as e:
            log_system_event(
                f"[{self._get_agent_type()}] 执行异常",
                {"error": str(e)},
                level=logging.ERROR,
            )
            return StructuredOutput(
                data=None,
                raw_text=f"执行异常: {str(e)}",
                tool_calls=[],
            )

    def get_session_id(self, thread_id: str = "default") -> Optional[str]:
        """获取会话 ID"""
        return self._sessions.get(thread_id)

    def clear_session(self, thread_id: str = "default"):
        """清除会话"""
        if thread_id in self._sessions:
            del self._sessions[thread_id]

    def clear_all_sessions(self):
        """清除所有会话"""
        self._sessions.clear()

    @property
    def session_count(self) -> int:
        """获取当前会话数量"""
        return len(self._sessions)


__all__ = [
    "BaseClaudeAgent",
    "StructuredOutput",
    "ResponseStreamResult",
    "SettingSource",
    "create_pre_tool_use_hook",
    "create_post_tool_use_hook",
    "create_subagent_stop_hook",
    "build_env_config",
]
