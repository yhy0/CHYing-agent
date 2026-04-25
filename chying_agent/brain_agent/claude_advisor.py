"""\
Claude SDK Orchestrator
=======================

基于 Claude Code SDK 实现的单会话编排器，通过环境变量映射支持任意模型（DeepSeek/MiniMax 等）。

特点：
- 继承 BaseClaudeAgent，复用公共功能
- 使用持久会话模式，支持多轮对话
- 通过环境变量映射使用第三方模型
- 支持 MCP 工具调用 + 内建子代理（Task）
- 利用 Claude SDK 的上下文管理能力
- 根据题目类型/模式自动选择专业化 Prompt

MCP 集成：
- 内置 MCP 工具通过 `claude_sdk.mcp_tools` 提供
- chrome-devtools 通过 visibility=subagent:browser 注册，仅 browser 子代理可见
- ghidra-mcp 通过 visibility=subagent:reverse 注册，仅 reverse 子代理可见
- Orchestrator 不可见任何 subagent:* 的工具，不污染上下文
- Claude SDK 自动发现并注册 MCP 工具
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional, Any, Dict, List

from claude_agent_sdk import AgentDefinition

from ..common import log_system_event
from ..claude_sdk import BaseClaudeAgent, ResponseStreamResult
from ..claude_sdk.schemas import ORCHESTRATOR_OUTPUT_SCHEMA
from ..claude_sdk.mcp_tools import get_chying_sdk_mcp_servers
from ..utils.path_utils import get_host_agent_work_dir
from .prompts import get_brain_prompt


class ClaudeOrchestrator(BaseClaudeAgent):
    """新架构主会话：允许 `Task` + 自定义 MCP tools，负责单会话自循环推进。"""

    # 不使用白名单（allowed_tools 返回空列表 → Hook 跳过白名单检查）
    # 只通过黑名单控制禁止使用的工具
    #
    # Chrome DevTools 和 Ghidra 工具通过 MCP Visibility 机制精确隔离：
    # - chrome-devtools: visibility=subagent:browser → 仅 browser 子代理可见
    # - ghidra-mcp: visibility=subagent:reverse → 仅 reverse 子代理可见
    # Orchestrator 和其他子代理（executor 等）均不可见，不污染上下文。
    DISALLOWED_TOOLS: List[str] = [
        "WebSearch",  # 先禁止搜索引擎（防止搜到 writeup 作弊，发现做 wiz 的挑战，直接搜到了别人的博客，学习到了解题思路）
        "WebFetch",
        "AskUserQuestion",
        "TodoWrite",       # CTF 解题不需要 todo，浪费工具调用
        # ---- CTF 解题不需要的工具，disallow 后其定义不会进入 prompt ----
        # 移除可节省 ~17K chars (~4,400 tokens) 上下文空间
        "EnterPlanMode",   # 4,795 chars - 规划模式
        "ExitPlanMode",    # 2,575 chars
        "EnterWorktree",   # 1,796 chars - Git worktree 隔离
        "ExitWorktree",    # 2,531 chars
        "CronCreate",      # 4,063 chars - 定时任务
        "CronDelete",      #   ~500 chars
        "CronList",        #   ~300 chars
        "NotebookEdit",    #   ~800 chars - Jupyter notebook
    ]

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        category: Optional[str] = None,
        mode: str = "ctf",
        cli_path: Optional[str] = None,
        work_dir: Optional[str] = None,
    ):
        """
        初始化 Orchestrator

        Args:
            model: 模型名称（默认从环境变量读取）
            base_url: API 基础 URL（默认从环境变量读取）
            api_key: API 密钥（默认从环境变量读取）
            category: 题目类型（misc, web, pwn, crypto, reverse）用于选择专业化 Prompt
            mode: 运行模式（ctf, pentest）用于选择专业化 Prompt
            cli_path: 自定义 CLI 路径（设置后 API 配置自动失效，由 CLI 管理认证和模型路由）
        """
        _cli_path = cli_path or os.getenv("CLAUDE_CLI_PATH") or None
        _model = model or os.getenv("LLM_MODEL") or None
        _api_key = api_key or os.getenv("LLM_API_KEY") or None
        _base_url = base_url or os.getenv("LLM_BASE_URL") or None

        # 备选模型（双模型交替运行，Guidance Loop 每轮轮换）
        _alt_model = os.getenv("LLM_MODEL_ALT") or None
        _alt_api_key = os.getenv("LLM_API_KEY_ALT") or None
        _alt_base_url = os.getenv("LLM_BASE_URL_ALT") or None

        _cwd = work_dir or str(get_host_agent_work_dir())

        # system prompt = 完全自定义的领域 prompt（替换 CLI 默认 prompt）
        # CLI 默认 prompt（文件操作规范、git 协议等）对 CTF 场景无用，不保留
        # 工具集通过 use_claude_code_preset=True 的 tools preset 独立启用
        system_prompt = get_brain_prompt()

        # 响应语言配置
        response_language = os.getenv("RESPONSE_LANGUAGE", "").strip().lower()
        if response_language == "zh-cn":
            system_prompt += "\n\n<language>请始终使用中文（简体）回答。</language>"
        elif response_language and response_language != "en":
            # 支持其他语言（如 ja, ko 等）
            system_prompt += f"\n\n<language>Always respond in {response_language}.</language>"

        log_system_event(
            "[Orchestrator] 使用专业化 Prompt",
            {
                "category": category,
                "mode": mode,
                "language": response_language or "default",
                "prompt_length": len(system_prompt),
                "alt_model": _alt_model,
            },
        )

        super().__init__(
            model=_model,
            system_prompt=system_prompt,
            max_turns=int(os.getenv("MAX_TURNS", "30")),
            enable_hooks=True,
            cwd=_cwd,
            api_key=_api_key,
            base_url=_base_url,
            cli_path=_cli_path,
            persistent_session=True,
            use_claude_code_preset=True,
            sandbox_enabled=True,
            sandbox_auto_allow_bash=True,
            sandbox_allow_local_binding=True,
            setting_sources=["project"],
            alt_model=_alt_model,
            alt_api_key=_alt_api_key,
            alt_base_url=_alt_base_url,
        )

        # 保存 category/mode 用于后续日志
        self._category = category
        self._mode = mode

    def _get_agent_type(self) -> str:
        return "Orchestrator"

    def _get_disallowed_tools(self) -> List[str]:
        return self.DISALLOWED_TOOLS.copy()

    def _get_allowed_tools(self) -> List[str]:
        # 不使用白名单 → 返回空列表 → Hook 跳过白名单检查
        return []

    def _get_output_schema(self) -> Optional[Dict[str, Any]]:
        # Orchestrator 必须输出稳定的结构化结果，供上层解析。
        return ORCHESTRATOR_OUTPUT_SCHEMA

    def _get_mcp_servers(self) -> Optional[Dict[str, Dict[str, Any]]]:
        # 内建（进程内）MCP tools
        servers: Dict[str, Dict[str, Any]] = {}
        try:
            servers.update(get_chying_sdk_mcp_servers())
        except Exception as e:
            log_system_event(
                f"[{self._get_agent_type()}] MCP 服务器初始化失败: {e}",
                level=logging.WARNING,
            )

        # 从 agent-work/.mcp.json 加载 subagent-only 的 MCP 服务器
        # 配置中 visibility 控制工具对哪些代理可见：
        # - 'subagent:browser'  → 仅 browser 子代理可见（chrome-devtools）
        # - 'subagent:reverse'  → 仅 reverse 子代理可见（ghidra-mcp）
        # - 'subagent'          → 所有子代理可见
        # - 'all'               → 所有角色可见
        # Orchestrator 看不到 subagent / subagent:<name> 的工具
        mcp_json = Path(str(get_host_agent_work_dir())) / ".mcp.json"
        if mcp_json.exists():
            try:
                raw = json.loads(mcp_json.read_text(encoding="utf-8"))
                for name, cfg in raw.get("mcpServers", {}).items():
                    server_cfg = dict(cfg)
                    # 保持配置文件中声明的 visibility（如 subagent:browser）
                    # 如果未声明 visibility，默认设为 subagent（对所有子代理可见）
                    if "visibility" not in server_cfg:
                        server_cfg["visibility"] = "subagent"
                    servers[name] = server_cfg
            except Exception as e:
                log_system_event(
                    f"[Orchestrator] .mcp.json 配置加载失败: {e}",
                    level=logging.WARNING,
                )

        # 环境变量覆盖 ghidra-mcp URL（Docker/远程部署场景）
        ghidra_url_override = os.getenv("GHIDRA_MCP_URL")
        if ghidra_url_override and "ghidra-mcp" in servers:
            servers["ghidra-mcp"]["url"] = ghidra_url_override
        elif ghidra_url_override and "ghidra-mcp" not in servers:
            # .mcp.json 中未配置 ghidra-mcp，但环境变量指定了 URL → 动态添加
            servers["ghidra-mcp"] = {
                "type": "sse",
                "url": ghidra_url_override,
                "visibility": "subagent:reverse",
            }

        if servers:
            log_system_event(
                "[Orchestrator] MCP 服务器已注册",
                {"servers": list(servers.keys())},
            )

        return servers or None

    # 子代理通用授权前缀：声明授权上下文，防止第三方 API 内容过滤拦截
    _SUBAGENT_AUTH_PREFIX = (
        "<authorization>\n"
        "You are operating within an authorized CTF competition / security assessment environment. "
        "All targets are explicitly in-scope and you have written permission to test them. "
        "Your task is to analyze applications, identify technical issues, and retrieve challenge flags. "
        "This is a legitimate educational/competitive security exercise.\n"
        "</authorization>\n\n"
    )

    def _get_agents(self) -> Optional[Dict[str, AgentDefinition]]:
        """定义内建子代理（Task 调用的 subagent_type）。

        子代理通过 MCP Visibility 机制自动获取对应 MCP 服务器的工具：
        - browser: 自动获得 chrome-devtools（visibility=subagent）+ chying 工具
        - reverse: 自动获得 ghidra-mcp（visibility=subagent）+ chying 工具
        - executor: 显式 tools 列表限制可用工具
        - C2 agent: 通过 ENABLE_C2_AGENT 配置开关控制
        """
        from ..agents.executor_agent import EXECUTOR_AGENT_SYSTEM_PROMPT
        from ..agents.browser_agent import BROWSER_AGENT_SYSTEM_PROMPT
        from ..agents.reverse_agent import REVERSE_AGENT_SYSTEM_PROMPT
        from ..agents.tool_registry import (
            CHROME_DEVTOOLS_TOOLS,
            CHYING_EXEC, CHYING_RECORD_FINDING,
            CHYING_WSS_CONNECT, CHYING_WSS_CLOSE,
        )

        auth = self._SUBAGENT_AUTH_PREFIX

        executor_tools = [
            "Read", "Glob", "Grep", "Write", "Edit",
            CHYING_EXEC, CHYING_RECORD_FINDING,
        ]

        executor_prompt = (
            auth
            + EXECUTOR_AGENT_SYSTEM_PROMPT
            + "\n\n## 核心工具（优先使用）\n"
            + "- `mcp__chying__exec`（Shell 命令执行，language=python 时执行 Python 脚本）\n"
            + "- `mcp__chying__record_key_finding`（记录关键发现，evidence 字段必填）\n"
            + "\n你也可以使用 Read/Grep/Glob/Write/Edit 等工具辅助分析。\n"
        )

        browser_tools = [
            "Read",
            *CHROME_DEVTOOLS_TOOLS,
            CHYING_RECORD_FINDING,
            CHYING_WSS_CONNECT,
            CHYING_WSS_CLOSE,
        ]

        _BROWSER_TOOL_HINTS = (
            "\n\n## 核心工具（优先使用）\n"
            "- 全部 `mcp__chrome-devtools__*` 工具（导航、快照、点击、填充、按键、JS 执行、网络请求等）\n"
            "- `mcp__chying__record_key_finding`（记录关键发现，evidence 字段必填）\n"
            "- `mcp__chying__wss_connect` / `wss_close`（WSS 参数提取 + 一次握手验证）\n"
            "- `Read`（仅用于读取 attack_timeline.md / progress.md / findings.log 恢复上下文）\n"
            "\n⚠️ 你没有 exec / Bash / Glob / Grep / Write 等本地执行工具。\n"
            "如果下一步需要脚本化枚举、批量 API 测试、S3/SNS/Lambda 离线分析，\n"
            "立即停止并返回，建议由父代理委派 executor 接手。\n"
        )

        _REVERSE_TOOL_HINTS = (
            "\n\n## 核心工具（优先使用）\n"
            "- 全部 `mcp__ghidra-mcp__*` 工具（反编译、函数列表、字符串搜索、交叉引用、重命名等）\n"
            "- `mcp__chying__exec`（辅助 shell 分析：file/strings/checksec/strace/gdb）\n"
            "- `mcp__chying__exec`（language=python：分析脚本：struct 解包、密码学分析、angr/z3）\n"
            "- `mcp__chying__record_key_finding`（记录关键发现，evidence 字段必填）\n"
        )

        agents = {
            "executor": AgentDefinition(
                description=(
                    "安全执行专家（Kali Docker 环境）：接收目标任务后自主执行多步操作，返回结构化摘要。"
                    "负责本地脚本化枚举、批量 API 测试、云离线分析、PoC 编写与执行。"
                    "预装工具：nuclei(CVE扫描)、sqlmap(SQL注入)、ffuf(Web Fuzz)、nmap(端口扫描)、"
                    "hydra(暴力破解)、commix(命令注入)、pwntools(二进制利用)、hashcat/john(破解)等。"
                    "CVE参考库：/opt/tools/vulhub/ 包含数百个CVE的PoC和利用说明，"
                    "遇到已知CVE时先 `cat /opt/tools/vulhub/<产品>/<CVE编号>/README.md` 或 "
                    "`find /opt/tools/vulhub -path '*<CVE编号>*'` 查找现成PoC，避免手写错误payload。"
                    "nuclei模板：/root/.local/nuclei-templates/，优先用 nuclei 扫描验证CVE再手动利用。"
                    "遇到已知漏洞类型应优先使用对应工具，而非手写exploit。"
                ),
                prompt=executor_prompt,
                model="inherit",
                tools=executor_tools,
                maxTurns=int(os.getenv("EXECUTOR_SUBAGENT_MAX_TURNS", "10")),
            ),
            "browser": AgentDefinition(
                description=(
                    "浏览器操作专家：使用 chrome-devtools MCP 进行页面导航、DOM 操作、"
                    "网络请求分析、Cookie/Session 提取、WSS 参数探测。"
                    "专注浏览器上下文，不执行本地脚本。"
                    "需要脚本化枚举/批量测试时，由 executor 接手。"
                ),
                prompt=auth + BROWSER_AGENT_SYSTEM_PROMPT + _BROWSER_TOOL_HINTS,
                model="inherit",
                tools=browser_tools,
                maxTurns=int(os.getenv("BROWSER_SUBAGENT_MAX_TURNS", "10")),
            ),
            # reverse 子代理（不设 tools 限制）
            "reverse": AgentDefinition(
                description=(
                    "逆向工程专家：使用 Ghidra MCP 进行二进制反编译、函数分析、字符串搜索、"
                    "交叉引用、漏洞定位、Exploit 开发。"
                    "预装工具：全部 mcp__ghidra-mcp__*（除 open_program）及 exec/record_key_finding。"
                ),
                prompt=auth + REVERSE_AGENT_SYSTEM_PROMPT + _REVERSE_TOOL_HINTS,
                model="inherit",
                disallowedTools=["mcp__ghidra-mcp__open_program"],  # GUI-only，headless 不可用
                maxTurns=int(os.getenv("REVERSE_SUBAGENT_MAX_TURNS", "15")),
            ),
        }

        # C2 agent: 通过配置开关控制，默认开启
        # 关闭时不加载 prompt/工具，模型完全不知道 c2 存在，减少上下文开销
        enable_c2 = os.getenv("ENABLE_C2_AGENT", "true").strip().lower() not in ("0", "false", "no")
        if enable_c2:
            try:
                from ..agents.c2_agent import C2_AGENT_SYSTEM_PROMPT
                c2_tools = [
                    "Read", "Glob", "Grep", "Write", "Edit",
                    CHYING_EXEC, CHYING_RECORD_FINDING,
                ]
                c2_prompt = (
                    auth
                    + C2_AGENT_SYSTEM_PROMPT
                    + "\n\n## 核心工具（优先使用）\n"
                    + "- `mcp__chying__exec`（Shell 命令执行：tmux 管理、msfvenom、nmap 等非交互命令）\n"
                    + "- `mcp__chying__record_key_finding`（记录关键发现：会话、凭据、拓扑）\n"
                    + "\n你也可以使用 Read/Grep/Glob/Write/Edit 等工具辅助分析。\n"
                )
                agents["c2"] = AgentDefinition(
                    description=(
                        "后渗透与 C2 操作专家（Metasploit + tmux）：自主执行多步后渗透操作，"
                        "通过 tmux 管理 msfconsole 交互式会话，支持漏洞利用、Payload 生成、"
                        "会话管理、权限提升、横向移动、内网穿透。返回结构化摘要。"
                    ),
                    prompt=c2_prompt,
                    model="inherit",
                    tools=c2_tools,
                    maxTurns=int(os.getenv("C2_SUBAGENT_MAX_TURNS", "20")),
                )
                log_system_event("[Orchestrator] C2 agent 已启用")
            except ImportError:
                log_system_event(
                    "[Orchestrator] C2 agent 启用失败: c2_agent 模块未找到",
                    level=logging.WARNING,
                )

        # 日志：展示每个子代理对应的 MCP 服务器（基于 visibility 配置）
        mcp_json = Path(str(get_host_agent_work_dir())) / ".mcp.json"
        if mcp_json.exists():
            try:
                raw = json.loads(mcp_json.read_text(encoding="utf-8"))
                for agent_name in agents:
                    matched = [
                        name for name, cfg in raw.get("mcpServers", {}).items()
                        if cfg.get("visibility") in (
                            f"subagent:{agent_name}", "subagent", "all",
                        )
                    ]
                    if matched:
                        log_system_event(
                            f"[Orchestrator] 子代理 '{agent_name}' 可见 MCP: {matched}",
                        )
            except Exception:
                pass

        return agents

    async def run(self, context: str) -> ResponseStreamResult:
        """运行一次解题（主会话自循环）。"""
        full_prompt = context
        log_system_event(f"[Agent] full_prompt: \n\n{full_prompt}")

        # 自动初始化 progress.md（compact 后恢复锚点）
        _init_progress_file(context)

        return await self.query(full_prompt)

    def _pre_compact_flush(self, result: ResponseStreamResult) -> None:
        """compact 前将结构化输出的关键信息刷入 progress.md。

        覆盖 BaseClaudeAgent 的空实现。
        solved=false 触发续跑 compact 时调用，确保 compact 后
        agent 读 progress.md 能看到最新的攻击进度、已失败方法和下一步方向，
        避免重复已经做过的探索。
        """
        if not result.structured_data or not isinstance(result.structured_data, dict):
            return
        try:
            _flush_progress_before_compact(result.structured_data)
        except Exception as e:
            log_system_event(
                f"[Progress] pre-compact flush 失败: {e}",
                level=logging.WARNING,
            )


def _flush_progress_before_compact(structured_data: Dict[str, Any]) -> None:
    """将结构化输出的攻击进度写入 progress.md。

    更新主要恢复段落：
    - Current Phase: summary + blocked_reason（覆写）
    - Dead Ends: blocked_reason + evidence 中的失败项（追加去重）
    - Next Steps: next_steps 列表（覆写）
    - Key Artifacts: structured output 中声明的关键产物（追加去重）

    Attack Tree 由 record_key_finding 自动维护，不在此处理。
    """
    from ..runtime.context import get_current_work_dir

    work_dir = get_current_work_dir()
    if not work_dir:
        return

    progress_file = work_dir / "progress.md"
    if not progress_file.exists():
        return

    content = progress_file.read_text(encoding="utf-8")

    # -- Current Phase --
    summary = structured_data.get("summary", "")
    blocked_reason = structured_data.get("blocked_reason", "")
    if summary:
        phase_text = summary
        if blocked_reason:
            phase_text += f"\n\nBlocked: {blocked_reason}"
        content = re.sub(
            r"(## Current Phase\n\n).*?(?=\n## |\Z)",
            rf"\g<1>{phase_text}\n",
            content,
            flags=re.DOTALL,
        )

    # -- Dead Ends --
    # 仅记录真正的阻塞/死路，不把普通 evidence 混入 Dead Ends。
    if blocked_reason:
        dead_match = re.search(
            r"## Dead Ends.*?\n\n(.*?)(?=\n## |\Z)",
            content,
            re.DOTALL,
        )
        existing_dead = ""
        if dead_match:
            existing_dead = dead_match.group(1).strip()
            if existing_dead.startswith("(auto-updated"):
                existing_dead = ""

        new_entries = []
        if blocked_reason and blocked_reason not in existing_dead:
            new_entries.append(f"- Blocked: {blocked_reason}")
        if new_entries:
            dead_content = existing_dead
            if dead_content:
                dead_content += "\n"
            dead_content += "\n".join(new_entries)
            content = re.sub(
                r"(## Dead Ends.*?\n\n).*?(?=\n## |\Z)",
                rf"\g<1>{dead_content}\n",
                content,
                flags=re.DOTALL,
            )

    # -- Next Steps --
    next_steps = _derive_progress_next_steps(structured_data, existing_content=content)
    if next_steps:
        steps_content = "\n".join(f"- {s}" for s in next_steps)
        content = re.sub(
            r"(## Next Steps\n\n).*?(?=\n## |\Z)",
            rf"\g<1>{steps_content}\n",
            content,
            flags=re.DOTALL,
        )

    # -- Key Artifacts --
    artifact_items = _derive_progress_artifacts(structured_data)
    if artifact_items:
        content = _merge_progress_bullets_local(
            content,
            "Key Artifacts",
            artifact_items,
            max_items=8,
        )

    progress_file.write_text(content, encoding="utf-8")
    log_system_event(
        "[Progress] pre-compact flush 完成",
        {"sections_updated": ["Current Phase", "Dead Ends", "Next Steps", "Key Artifacts"]},
    )


def _merge_progress_bullets_local(
    content: str,
    section_title: str,
    items: list[str],
    *,
    max_items: int = 8,
) -> str:
    """本地合并 progress.md 的 bullet section。"""
    import re

    cleaned = [re.sub(r"\s+", " ", str(item).strip())[:220] for item in items if str(item).strip()]
    if not cleaned:
        return content

    existing: list[str] = []
    match = re.search(
        rf"## {re.escape(section_title)}\n\n(.*?)(?=\n## |\Z)",
        content,
        re.DOTALL,
    )
    if match:
        for line in match.group(1).splitlines():
            stripped = line.strip()
            if stripped.startswith("- "):
                existing.append(stripped[2:].strip())

    merged: list[str] = []
    seen: set[str] = set()
    for item in existing + cleaned:
        if item and item not in seen:
            seen.add(item)
            merged.append(item)

    if max_items > 0 and len(merged) > max_items:
        merged = merged[-max_items:]

    body = "\n".join(f"- {item}" for item in merged)
    pattern = re.compile(
        rf"(## {re.escape(section_title)}\n\n).*?(?=\n## |\Z)",
        re.DOTALL,
    )
    if pattern.search(content):
        return pattern.sub(r"\g<1>" + body + "\n", content)
    return content.rstrip() + f"\n\n## {section_title}\n\n{body}\n"


def _derive_progress_next_steps(
    structured_data: Dict[str, Any],
    *,
    existing_content: str = "",
) -> list[str]:
    """为 progress.md 推导非空的 Next Steps。

    优先使用模型显式给出的 next_steps。
    若为空，则保留已有的非占位内容；
    若仍为空，则从 blocked_reason / artifacts / attack_vectors / evidence / summary
    中提炼 1-5 条可执行提示，避免 compact 恢复后完全没有行动锚点。
    """
    def _clean_step(value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        text = re.sub(r"\s+", " ", text)
        return text[:220]

    steps: list[str] = []
    seen: set[str] = set()

    def _push(value: Any) -> None:
        text = _clean_step(value)
        if text and text not in seen:
            seen.add(text)
            steps.append(text)

    raw_steps = structured_data.get("next_steps", [])
    if isinstance(raw_steps, list):
        for item in raw_steps[:5]:
            _push(item)
    elif raw_steps:
        _push(raw_steps)
    if steps:
        return steps

    if existing_content:
        match = re.search(r"## Next Steps\n\n(.*?)(?=\n## |\Z)", existing_content, re.DOTALL)
        if match:
            existing_body = match.group(1).strip()
            placeholder = "(overwritten from structured output before compact)"
            if existing_body and placeholder not in existing_body:
                for line in existing_body.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("- "):
                        _push(stripped[2:])
                if steps:
                    return steps[:5]

    blocked_reason = structured_data.get("blocked_reason", "")
    if blocked_reason:
        _push(f"优先解决当前阻塞：{blocked_reason}")

    artifacts = structured_data.get("artifacts", [])
    if isinstance(artifacts, list):
        for artifact in artifacts[:3]:
            if not isinstance(artifact, dict):
                continue
            path = str(artifact.get("path", "")).strip()
            desc = str(artifact.get("description", "")).strip()
            if path:
                hint = f"检查产物 `{path}`"
                if desc:
                    hint += f"（{desc}）"
                _push(hint)

    attack_vectors = structured_data.get("attack_vectors", [])
    if isinstance(attack_vectors, list):
        for vector in attack_vectors[:2]:
            if not isinstance(vector, dict):
                continue
            name = str(vector.get("name", "")).strip()
            desc = str(vector.get("description", "")).strip()
            if name:
                hint = f"优先验证攻击向量：{name}"
                if desc:
                    hint += f"（{desc[:100]}）"
                _push(hint)

    evidence = structured_data.get("evidence", [])
    if isinstance(evidence, list):
        for item in evidence[:2]:
            _push(f"围绕关键证据继续推进：{item}")

    summary = structured_data.get("summary", "")
    if summary and not steps:
        _push(f"基于当前总结继续推进：{summary}")

    return steps[:5]


def _derive_progress_artifacts(structured_data: Dict[str, Any]) -> list[str]:
    """从结构化输出提取适合写入 progress.md 的关键产物列表。"""
    artifacts = structured_data.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []

    items: list[str] = []
    for artifact in artifacts[:5]:
        if not isinstance(artifact, dict):
            continue
        path = str(artifact.get("path", "")).strip()
        desc = str(artifact.get("description", "")).strip()
        if not path:
            continue
        item = f"`{path}`"
        if desc:
            item += f" — {desc}"
        items.append(item)
    return items


def _strip_prior_knowledge(context: str) -> str:
    """从编译后 context 中移除 <prior_knowledge> 段。

    prior_knowledge 是启动时的历史快照，后续会过时。
    agent 产生的新发现会记录到 findings.log 和 progress.md 中。
    """
    # 匹配 XML 标签版本（PromptCompiler 输出）
    cleaned = re.sub(
        r"<prior_knowledge>.*?</prior_knowledge>",
        "",
        context,
        flags=re.DOTALL,
    )
    # 匹配 markdown 标题版本（fallback context）
    cleaned = re.sub(
        r"## ⚠️ 历史执行信息[^\n]*\n.*?(?=\n## |\Z)",
        "",
        cleaned,
        flags=re.DOTALL,
    )
    return cleaned.strip()


def _init_progress_file(context: str) -> None:
    """在当前题目工作目录下初始化 progress.md。

    将编译后的任务上下文（去掉 prior_knowledge）写入 progress.md，
    作为 compact 后恢复题目信息的持久化锚点。

    只在 progress.md 不存在时创建，避免覆盖 agent 已更新的进度。
    """
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if not work_dir:
            return

        progress_file = work_dir / "progress.md"
        if progress_file.exists():
            # 已存在（可能是重试场景），不覆盖 agent 已更新的进度
            log_system_event(
                "[Progress] progress.md 已存在，跳过初始化",
                {"path": str(progress_file)},
            )
            return

        # 从 context 中去掉 prior_knowledge（会过时，DB 已持久化）
        task_context = _strip_prior_knowledge(context)

        content = (
            "# Challenge Progress\n\n"
            "## Compiled Task Context (for compact recovery)\n\n"
            "Task context generated by PromptCompiler: challenge analysis, attack plan, constraints.\n"
            "Re-read this section after compact to restore challenge info.\n\n"
            f"{task_context}\n\n"
            "---\n\n"
            "## 🎯 ACTIVE TARGET\n\n"
            "(auto-updated when a finding reaches status=confirmed — verbatim evidence from tool output)\n\n"
            "## Attack Tree\n\n"
            "(auto-updated from record_key_finding: title + evidence per entry, supports updates)\n\n"
            "## Dead Ends (DO NOT RETRY)\n\n"
            "(auto-updated from record_key_finding(kind=dead_end) and structured output flush)\n\n"
            "## Current Phase\n\n"
            "Initialization\n\n"
            "## Next Steps\n\n"
            "(overwritten from structured output before compact)\n\n"
            "## Key Artifacts\n\n"
            "(auto-synced from structured output / subagent artifact_paths / hint persistence)\n\n"
            "## Hints Used\n\n"
            "(auto-synced from view_hint and hint.md)\n"
        )

        progress_file.write_text(content, encoding="utf-8")
        log_system_event(
            "[Progress] progress.md 已初始化",
            {"path": str(progress_file), "size": len(content)},
        )

    except Exception as e:
        # 非关键路径，失败不影响解题
        log_system_event(
            f"[Progress] progress.md 初始化失败: {e}",
            level=logging.WARNING,
        )
