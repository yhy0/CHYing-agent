"""Claude SDK in-process MCP tools

这里的目标不是替代 Claude 的内建 Subagent，而是为 Orchestrator/子代理提供**可控的执行能力**：
- 在 Kali Docker 容器内执行命令（复用现有 DockerExecutor 与 workdir 映射）
- 在 Docker 容器内执行 Python PoC
- 记录关键发现到 DB + 题目工作目录 markdown（pointer-only）
- 记忆搜索：搜索历史记录、列出工作目录、获取题目信息

设计原则：
- 工具输出遵循"长输出落盘 + 返回摘要指针"，避免污染会话上下文
- 工具输入做最小校验（空命令/空代码/过长输入）
- 与现有工程骨架兼容：workdir 隔离、history 记录、DB recorder

注意：
- 这些 tools 通过 `create_sdk_mcp_server` 以进程内 MCP server 形式提供给 Claude Code SDK。
- tool 的调用/结果记录主要由 `BaseClaudeAgent` 的 hooks 负责（history.jsonl），这里避免重复记录。
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from claude_agent_sdk import tool, create_sdk_mcp_server

from chying_agent.common import log_system_event, log_kb_event
from chying_agent.runtime.singleton import get_config_manager
from chying_agent.runtime.context import get_current_work_dir
from chying_agent.utils.output_utils import save_long_output
from chying_agent.utils.path_utils import (
    DOCKER_AGENT_WORK_PREFIX,
    convert_host_path_to_docker,
    get_host_agent_work_dir,
    is_in_container,
)
from chying_agent.claude_sdk.wss_terminal_client import get_session_manager


_logger = logging.getLogger(__name__)

# 复用现有阈值（与 `tools/shell.py` 一致的量级）
MAX_OUTPUT_LENGTH = 40000

# Docker 容器中 agent-work 的映射路径
DOCKER_AGENT_WORK_ROOT = Path(DOCKER_AGENT_WORK_PREFIX)
# 宿主机 agent-work 的路径
HOST_AGENT_WORK_ROOT = get_host_agent_work_dir()


def _append_hint_markdown(hint_text: str) -> None:
    """将 view_hint 返回结果追加写入当前题目的 hint.md。"""
    hint_body = (hint_text or "").strip()
    if not hint_body:
        return

    work_dir = get_current_work_dir()
    if work_dir is None:
        return

    hint_file = Path(work_dir) / "hint.md"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = "# Hint History\n\n" if not hint_file.exists() else ""
    entry = (
        f"## {timestamp}\n\n"
        f"{hint_body}\n\n"
        "---\n\n"
    )
    with open(hint_file, "a", encoding="utf-8") as f:
        f.write(header + entry)


def _record_submitted_flag(flag: str, ok: bool, message: str) -> None:
    """将 submit_flag 提交结果持久化到当前题目的 findings.log。"""
    work_dir = get_current_work_dir()
    if work_dir is None:
        return

    findings_file = Path(work_dir) / "findings.log"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    status = "accepted" if ok else "rejected"
    entry = (
        f"\n---\n"
        f"time: {timestamp}\n"
        f"kind: flag\n"
        f"status: {status}\n"
        f"value: {flag}\n"
        f"message: {message}\n"
    )
    with open(findings_file, "a", encoding="utf-8") as f:
        f.write(entry)




def _get_docker_work_dir() -> Optional[str]:
    """将宿主机工作目录映射为容器内路径。容器内模式直接返回本地路径。"""
    host_work_dir = get_current_work_dir()
    if host_work_dir is None:
        return None

    if is_in_container():
        return str(host_work_dir)

    try:
        relative_path = host_work_dir.relative_to(HOST_AGENT_WORK_ROOT)
        docker_path = DOCKER_AGENT_WORK_ROOT / relative_path
        return str(docker_path)
    except ValueError:
        return None


def _rewrite_agent_work_prefixes(text: str, *, to_docker: bool) -> str:
    """将文本中的 agent-work 绝对路径在 host/docker 语义间重写。"""
    if not text or is_in_container():
        return text

    host_root = str(get_host_agent_work_dir()).rstrip("/")
    docker_root = convert_host_path_to_docker(host_root).rstrip("/")

    src_root = host_root if to_docker else docker_root
    dst_root = docker_root if to_docker else host_root

    return text.replace(f"{src_root}/", f"{dst_root}/").replace(src_root, dst_root)


def _get_passthrough_env() -> dict[str, str] | None:
    """获取白名单环境变量，为空则返回 None"""
    env = get_config_manager().config.docker.passthrough_env
    return env or None


def _format_exec_output(*, exit_code: int, stdout: str, stderr: str) -> str:
    out = f"""Exit Code: {exit_code}

--- STDOUT ---
{stdout}

--- STDERR ---
{stderr}
"""
    # 归一化 \r 输出（避免后续工具读取/grep 失效）
    return out.replace("\r\n", "\n").replace("\r", "\n")


def _as_text_result(text: str, *, is_error: bool = False) -> Dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": text,
            }
        ],
        "is_error": is_error,
    }


def _validate_non_empty(value: str, *, field: str) -> Optional[str]:
    if not value or not str(value).strip():
        return f"错误：{field} 不能为空"
    return None


def _truncate_str(value: str, max_len: int) -> str:
    v = (value or "").strip()
    return v if len(v) <= max_len else v[: max_len - 3] + "..."


def _sanitize_source(source: Dict[str, Any]) -> Dict[str, Any]:
    """Source 必须是 pointer-only JSON dict。

    只保留 allowlist 字段，避免把大段输出/嵌套对象写进 memory。
    """

    allow = {
        "tool",
        "file",
        "url",
        "host",
        "port",
        "service",
        "path",
        "hash",
        "user",
        "session",
        "note",
    }

    out: Dict[str, Any] = {}
    for k, v in (source or {}).items():
        if k not in allow:
            continue

        if isinstance(v, str):
            out[k] = _truncate_str(v, 200)
        elif isinstance(v, (int, float, bool)) or v is None:
            out[k] = v
        else:
            out[k] = _truncate_str(str(v), 200)

    return out


def _append_key_finding_markdown(
    *,
    kind: str,
    title: str,
    evidence: str,
    details: str,
    meta: Dict[str, Any],
) -> None:
    """将关键发现追加到当前题目目录 findings.log（append-only 结构化格式）。

    格式设计原则：
    - 新 agent 看到一条 finding 就能判断：结论是否可信、哪些方法已验证、哪些方向还没试
    - verification_method + commands_and_results 构成可验证证据链
    - paths_not_tried 为新 agent 提供优先尝试的候选路径
    """

    work_dir = get_current_work_dir()
    if not work_dir:
        return

    md_path = work_dir / "findings.log"

    try:
        import datetime as _dt

        ts = _dt.datetime.now().isoformat(timespec="seconds")
    except Exception:
        ts = ""

    status = meta.get("status", "hypothesis")
    verification = meta.get("verification_method", "inferred")
    confidence = meta.get("confidence")

    # 验证可信度标签
    trust_label = {
        "executed": "VERIFIED-BY-EXECUTION",
        "observed": "OBSERVED",
        "inferred": "UNVERIFIED-INFERENCE",
    }.get(verification, "UNKNOWN")

    header = f"### {ts} [{kind}] {title} [{trust_label}]".strip()

    lines = [
        header,
        "",
        f"- status: {status}",
        f"- verification: {verification}",
    ]
    if confidence is not None:
        lines.append(f"- confidence: {confidence}")

    # 核心结论
    lines.extend(["", f"**evidence**: {evidence}"])

    # 已执行的命令和结果（可验证证据）
    commands = meta.get("commands_and_results")
    if commands:
        lines.extend([
            "",
            "**commands_and_results**:",
            commands,
        ])

    # 已尝试的攻击路径
    paths_tried = meta.get("paths_tried")
    if paths_tried:
        lines.extend([
            "",
            "**paths_tried**:",
            paths_tried,
        ])

    # 未尝试的方向（新 agent 的候选路径）
    paths_not_tried = meta.get("paths_not_tried")
    if paths_not_tried:
        lines.extend([
            "",
            "**paths_not_tried** (candidates for next agent):",
            paths_not_tried,
        ])

    # 建议的下一步
    next_action = meta.get("next_action")
    if next_action:
        lines.extend(["", f"**next_action**: {next_action}"])

    # 被否定的假设（dead_end 结构化分析）
    blocked_assumption = meta.get("blocked_assumption")
    if blocked_assumption:
        lines.extend([
            "",
            "**blocked_assumption**:",
            blocked_assumption,
        ])

    # 来源
    source = meta.get("source")
    if source:
        lines.append(f"- source: {source}")

    # 完整过程（writeup 用）
    if details:
        lines.extend(["", "**details**:", details.strip()])

    lines.extend(["", "---", ""])

    existing = ""
    if md_path.exists():
        existing = md_path.read_text(encoding="utf-8")
        if existing and not existing.endswith("\n"):
            existing += "\n"

    md_path.write_text(existing + "\n".join(lines), encoding="utf-8")


def _sync_finding_to_progress(
    *,
    kind: str,
    title: str,
    evidence: str,
    details: str,
    meta: Dict[str, Any],
) -> None:
    """将关键发现自动同步到 progress.md。

    根据 kind 路由到不同段落：
    - dead_end/blocked -> Dead Ends 段落（追加去重）
    - 其他 -> Attack Tree 段落（原地更新或追加）

    Attack Tree 支持按 title 更新已有条目（证据刷新），不再跳过。
    """
    work_dir = get_current_work_dir()
    if not work_dir:
        return

    progress_file = work_dir / "progress.md"
    if not progress_file.exists():
        return

    content = progress_file.read_text(encoding="utf-8")

    is_dead_end = kind in ("dead_end", "blocked")

    confidence = meta.get("confidence")
    conf_str = f" (conf={confidence})" if confidence is not None else ""

    if is_dead_end:
        entry_line = f"- **[{kind}]** {title}{conf_str}"
        section_pattern = re.compile(
            r"(## Dead Ends[^\n]*\n\n)(.*?)(?=\n## |\Z)",
            re.DOTALL,
        )
    else:
        entry_line = f"- [x] **[{kind}]** {title}{conf_str}"
        section_pattern = re.compile(
            r"(## Attack Tree\n\n)(.*?)(?=\n## |\Z)",
            re.DOTALL,
        )

    evidence_line = f"  evidence: {evidence}" if evidence else ""

    match = section_pattern.search(content)
    if match:
        existing_section = match.group(2).strip()
        if existing_section.startswith("(auto-updated"):
            existing_section = ""

        if is_dead_end:
            if title in existing_section:
                return
            new_entry = entry_line
            if evidence_line:
                new_entry += "\n" + evidence_line
            # blocked_assumption 结构化解析：提取 scope 和 untested 信息
            blocked_assumption = meta.get("blocked_assumption") or ""
            if blocked_assumption:
                scope = "unknown"
                untested = ""
                for ba_line in blocked_assumption.split("\n"):
                    ba_line_stripped = ba_line.strip()
                    ba_lower = ba_line_stripped.lower()
                    if ba_lower.startswith("覆盖范围:") or ba_lower.startswith("覆盖范围：") or "scope:" in ba_lower:
                        if "direction_wide" in ba_lower:
                            scope = "direction_wide"
                        elif "method_only" in ba_lower:
                            scope = "method_only"
                    elif ba_lower.startswith("未测试替代:") or ba_lower.startswith("未测试替代：") or "untested:" in ba_lower:
                        untested = ba_line_stripped.split(":", 1)[-1].strip() if ":" in ba_line_stripped else ""
                        if not untested and "\uff1a" in ba_line_stripped:
                            untested = ba_line_stripped.split("\uff1a", 1)[-1].strip()
                new_entry += f"\n  scope: {scope}"
                if untested:
                    new_entry += f"\n  untested: {untested}"
            new_section = (
                f"{existing_section}\n{new_entry}" if existing_section else new_entry
            )
        else:
            lines = existing_section.split("\n") if existing_section else []
            new_lines: list[str] = []
            found = False
            i = 0
            while i < len(lines):
                line = lines[i]
                if title in line and line.strip().startswith("- ["):
                    found = True
                    i += 1
                    while i < len(lines) and lines[i].startswith("  "):
                        i += 1
                    new_lines.append(entry_line)
                    if evidence_line:
                        new_lines.append(evidence_line)
                    continue
                new_lines.append(line)
                i += 1

            if not found:
                new_lines.append(entry_line)
                if evidence_line:
                    new_lines.append(evidence_line)

            new_section = "\n".join(new_lines)

        content = section_pattern.sub(
            r"\g<1>" + new_section.strip() + "\n", content
        )
    else:
        new_entry = entry_line
        if evidence_line:
            new_entry += "\n" + evidence_line
        section_name = "## Dead Ends (DO NOT RETRY)" if is_dead_end else "## Attack Tree"
        content = content.rstrip() + f"\n\n{section_name}\n\n{new_entry}\n"

    progress_file.write_text(content, encoding="utf-8")


def _update_active_target(
    *,
    title: str,
    evidence: str,
    status: str,
    next_action: Optional[str],
) -> None:
    """将 confirmed/exploited finding 写入 progress.md 顶部的 ACTIVE TARGET 区域。

    设计原则：
    - 只保留**一条**当前最高优先级目标（exploited > confirmed，后写覆盖前写）
    - 内容是 verbatim evidence + next_action，不让 LLM 重新生成叙述
    - compact 后 LLM 读 progress.md 第一屏就能看到"下一步要干什么"，显著性最高
    - exploited 状态时清空 ACTIVE TARGET（漏洞已利用完毕，无需继续聚焦）
    """
    work_dir = get_current_work_dir()
    if not work_dir:
        return

    progress_file = work_dir / "progress.md"
    if not progress_file.exists():
        return

    content = progress_file.read_text(encoding="utf-8")

    section_pattern = re.compile(
        r"(## 🎯 ACTIVE TARGET\n\n)(.*?)(?=\n## |\Z)",
        re.DOTALL,
    )

    if status == "exploited":
        # 漏洞已利用，清空 ACTIVE TARGET
        new_body = "(漏洞已利用完毕，继续寻找 FLAG)\n"
    else:
        # confirmed：置顶显示，verbatim evidence
        action_line = f"\n**Next**: {next_action}" if next_action else ""
        new_body = (
            f"**{title}**\n\n"
            f"```\n{evidence}\n```"
            f"{action_line}\n"
        )

    if section_pattern.search(content):
        content = section_pattern.sub(
            r"\g<1>" + new_body,
            content,
        )
    else:
        # Section 不存在时插入到 Compiled Task Context 之后、Attack Tree 之前
        insertion_point = re.search(r"\n## Attack Tree", content)
        if insertion_point:
            insert_at = insertion_point.start()
            content = (
                content[:insert_at]
                + "\n\n## 🎯 ACTIVE TARGET\n\n"
                + new_body
                + content[insert_at:]
            )

    progress_file.write_text(content, encoding="utf-8")


@tool(
    name="exec",
    description="在 Kali Docker 容器中执行命令或 Python 脚本。"
    "language=shell(默认): 执行 shell 命令，自动 cd 到题目工作目录（用相对路径即可）。"
    "language=python: 执行 Python PoC（自动 workdir 注入、语法检查、脚本存档）。"
    "长输出自动落盘。",
    input_schema={
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "shell command 或 Python code"},
            "language": {
                "type": "string",
                "enum": ["shell", "python"],
                "description": "执行语言: shell(默认) 或 python",
                "default": "shell",
            },
            "timeout": {"type": "integer", "description": "timeout in seconds (default 300, max 600)", "default": 300},
        },
        "required": ["command"],
    },
)
async def exec_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    command = str(args.get("command", ""))
    language = str(args.get("language", "shell")).lower()
    timeout = min(int(args.get("timeout", 300)), 600)

    err = _validate_non_empty(command, field="command")
    if err:
        return _as_text_result(err, is_error=True)

    is_python = language == "python"
    # LLM 看到的是宿主机 agent-work 绝对路径；exec 实际运行在 Docker 中。
    # 这里统一把命令中的 agent-work 前缀映射到容器路径，避免出现 exec/Read 两套路径世界。
    command_for_exec = _rewrite_agent_work_prefixes(command, to_docker=True)

    # Python 模式：语法检查 + PoC 存档 + workdir 注入
    if is_python:
        try:
            compile(command, "<poc>", "exec")
        except SyntaxError as e:
            return _as_text_result(
                f"语法错误（第 {e.lineno} 行）: {e.msg}\n提示：请检查缩进/引号/括号是否正确",
                is_error=True,
            )
        except Exception as e:
            return _as_text_result(f"代码验证失败: {e}", is_error=True)

        # 保存 PoC 脚本
        try:
            _poc_work_dir = get_current_work_dir()
            if _poc_work_dir:
                from datetime import datetime as _dt

                _ts = _dt.now().strftime("%Y%m%d_%H%M%S")
                _poc_dir = _poc_work_dir / "poc_scripts"
                _poc_dir.mkdir(parents=True, exist_ok=True)
                (_poc_dir / f"poc_{_ts}.py").write_text(command, encoding="utf-8")
        except Exception:
            pass

    docker_work_dir = _get_docker_work_dir()

    if is_python:
        # Python workdir 注入
        if docker_work_dir:
            injection = (
                "# === 自动注入：工作目录设置 ===\n"
                "import os\n"
                f"WORK_DIR = {json.dumps(docker_work_dir)}\n"
                "os.environ['WORK_DIR'] = WORK_DIR\n"
                "os.chdir(WORK_DIR)\n"
                "# === 注入结束 ===\n\n"
            )
            command_for_exec = injection + command_for_exec

        try:
            result = get_config_manager().executor.execute(
                command_for_exec, timeout=timeout, is_python=True,
                caller="exec[python]", environment=_get_passthrough_env(),
            )
        except Exception as e:
            return _as_text_result(f"执行异常: {e}", is_error=True)
    else:
        # Shell 模式
        if docker_work_dir:
            log_system_event("[MCP] exec.workdir", {"docker_work_dir": docker_work_dir})

        try:
            executor = get_config_manager().executor
            result = executor.execute(command_for_exec, timeout=timeout, workdir=docker_work_dir,
                                      caller="exec[shell]", environment=_get_passthrough_env())
        except Exception as e:
            return _as_text_result(f"执行异常: {e}", is_error=True)

        # Shell 命令日志
        try:
            _cmd_work_dir = get_current_work_dir()
            if _cmd_work_dir:
                from datetime import datetime as _dt

                _ts = _dt.now().isoformat(timespec="seconds")
                _exit = int(result.exit_code) if result.exit_code is not None else -1
                _dumps_dir = _cmd_work_dir / "dumps"
                _dumps_dir.mkdir(parents=True, exist_ok=True)
                with open(_dumps_dir / "commands.log", "a", encoding="utf-8") as _f:
                    _f.write(f"[{_ts}] exit={_exit} $ {command}\n")
        except Exception:
            pass

    exit_code = int(result.exit_code) if result.exit_code is not None else -1
    stdout = _rewrite_agent_work_prefixes(str(result.stdout or ""), to_docker=False)
    stderr = _rewrite_agent_work_prefixes(str(result.stderr or ""), to_docker=False)
    output = _format_exec_output(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
    )
    # 非零退出码视为错误，让模型感知到"这次调用失败了"而不是把错误当成普通文本
    exec_failed = exit_code != 0

    if len(output) > MAX_OUTPUT_LENGTH:
        cmd_prefix = (
            "python_poc" if is_python
            else (command.split()[0].replace("/", "_") if command else "shell")
        )
        _, summary = save_long_output(output, cmd_prefix)
        return _as_text_result(summary, is_error=exec_failed)

    return _as_text_result(output, is_error=exec_failed)


@tool(
    name="record_key_finding",
    description="记录关键发现（结构化格式）。"
    "每条记录必须区分'已验证'和'仅推测'——下次 retry 的 agent 只看 findings.log 来决定下一步。"
    "如果你没有实际执行命令就记录 dead_end，新 agent 会跳过本应尝试的攻击路径。",
    input_schema={
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "description": "发现类型: vulnerability, credential, info, config, note, dead_end",
            },
            "title": {
                "type": "string",
                "description": "发现标题（概括核心内容，同时用于 upsert 去重）",
            },
            "status": {
                "type": "string",
                "description": "验证状态（必须准确反映实际验证程度）:\n"
                "- hypothesis: 纯推测，未执行任何验证命令\n"
                "- tested: 已执行命令验证（无论成功失败）\n"
                "- confirmed: 验证后确认可利用\n"
                "- exploited: 已成功利用获得结果\n"
                "- dead_end: 经过实际测试确认为死路（禁止未测试就标 dead_end）",
            },
            "verification_method": {
                "type": "string",
                "description": "结论的验证方式:\n"
                "- executed: 实际执行了命令/请求并观察到结果\n"
                "- observed: 从输出/响应中观察到（未主动测试）\n"
                "- inferred: 根据其他证据推断（未直接验证）",
            },
            "commands_and_results": {
                "type": "string",
                "description": "已执行的关键命令及其结果（多行文本）。每行格式: `command` -> result (exit_code)。"
                "这是最重要的可验证证据，新 agent 看到后可以判断结论是否可信。"
                "示例:\n"
                "  `ls -la /home/tfuser/.terraform*` -> No such file (exit=2)\n"
                "  `echo test > /home/tfuser/test.txt` -> Permission denied (exit=1)",
            },
            "paths_tried": {
                "type": "string",
                "description": "已尝试的攻击路径/方法摘要（编号列表）。每条简述方法和结果。"
                "示例:\n"
                "  1. 直接写入 .terraform 目录 -> 权限拒绝\n"
                "  2. TF_DATA_DIR 环境变量覆盖 -> state 未被注入",
            },
            "paths_not_tried": {
                "type": "string",
                "description": "想到但未实际执行的方向（编号列表）。说明未尝试的原因。"
                "这些是新 agent 优先尝试的候选路径。"
                "示例:\n"
                "  1. symlink 攻击（仅理论推测，未实际执行 ln -s 命令）\n"
                "  2. data source 注入（需要写权限，已知无法写入目标目录但未测试其他位置）",
            },
            "blocked_assumption": {
                "type": "string",
                "description": "(dead_end 时必填，否则工具会报错) 被否定的假设及覆盖范围。格式:\n"
                "假设: [原来以为什么]\n"
                "否定证据: [什么事实否定了]\n"
                "覆盖范围: method_only(只此方法不行) / direction_wide(整个方向不通)\n"
                "未测试替代: [同方向下未测试的其他方法]",
            },
            "evidence": {
                "type": "string",
                "description": "结论摘要（1-2 行）。从上面的命令结果中得出的核心结论。"
                "compact 后 Agent 看到它就能继续下一步而不需要重新探索。"
                "示例: 'POST /create-user skipRecaptcha=true -> user=admin@victim.com (pwd: Pass123)'",
            },
            "next_action": {"type": "string", "description": "建议的下一步操作及原因"},
            "details": {
                "type": "string",
                "description": "完整推导/利用过程（可选）。包含操作步骤、中间失败、技术分析。"
                "用于生成 writeup，内容越详细 writeup 质量越高。",
            },
            "source": {
                "type": "object",
                "description": "来源指针",
                "properties": {
                    "tool": {"type": "string"},
                    "file": {"type": "string"},
                    "url": {"type": "string"},
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                    "service": {"type": "string"},
                    "path": {"type": "string"},
                    "user": {"type": "string"},
                    "note": {"type": "string"},
                },
            },
            "confidence": {"type": "number", "description": "置信度 0.0-1.0"},
        },
        "required": ["kind", "title", "evidence", "status", "verification_method"],
    },
)
async def record_key_finding_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    kind = str(args.get("kind", "")).strip() or "note"
    title = str(args.get("title", "")).strip() or "Unknown"
    evidence = str(args.get("evidence", "")).strip()
    details = str(args.get("details", "")).strip()
    next_action = str(args.get("next_action", "")).strip()
    status = str(args.get("status", "hypothesis")).strip() or "hypothesis"
    verification_method = str(args.get("verification_method", "inferred")).strip() or "inferred"
    commands_and_results = str(args.get("commands_and_results", "")).strip()
    paths_tried = str(args.get("paths_tried", "")).strip()
    paths_not_tried = str(args.get("paths_not_tried", "")).strip()
    blocked_assumption = str(args.get("blocked_assumption", "")).strip()

    if not evidence:
        return _as_text_result(
            "evidence 不能为空。请提供最小可复现证据（关键命令/请求 + 关键结果）。"
            "示例: 'curl -X POST .../api -d \"user=admin\" -> 200 OK, token=eyJ...'",
            is_error=True,
        )

    # confirmed/exploited 必须基于实际执行，防止把工作假设写成已验证结论污染 findings
    if status in ("confirmed", "exploited"):
        if verification_method == "inferred":
            return _as_text_result(
                f"status='{status}' 要求实际执行验证，verification_method 不能是 'inferred'。\n"
                "请提供:\n"
                "1. verification_method='executed'（实际执行了命令/请求）或 'observed'（直接观察到结果）\n"
                "2. commands_and_results 中列出关键命令及其输出\n"
                "如果你还没有实际测试，请改用 status='hypothesis'（纯推测）或 status='tested'（已执行但未确认可利用）。",
                is_error=True,
            )
        if not commands_and_results:
            return _as_text_result(
                f"status='{status}' 要求在 commands_and_results 中提供验证证据。\n"
                "格式示例:\n"
                "  `curl -X POST /api/login -d 'user=admin&pass=123'` -> 200 OK, token=eyJ... (exit=0)\n"
                "  `curl /flag` -> flag{{...}} (exit=0)\n"
                "如果你只有推断而无实际命令输出，请改用 status='hypothesis' 或 status='tested'。",
                is_error=True,
            )

    # dead_end 必须有实际验证证据 + blocked_assumption 强制区分 method/direction failure
    if kind == "dead_end" or status == "dead_end":
        if verification_method == "inferred" and not commands_and_results:
            return _as_text_result(
                "dead_end 必须基于实际验证。请提供:\n"
                "1. verification_method='executed' 或 'observed'\n"
                "2. commands_and_results 中列出实际执行的命令及结果\n"
                "如果你没有实际测试，请用 status='hypothesis' + kind='note' 记录推测。",
                is_error=True,
            )
        if not blocked_assumption:
            return _as_text_result(
                "dead_end 必须填写 blocked_assumption 字段，区分 method failure 和 direction failure。\n"
                "格式（4 行）:\n"
                "假设: [原来以为什么可以行得通]\n"
                "否定证据: [哪条命令/结果否定了这个假设]\n"
                "覆盖范围: method_only（仅此方法不行，同方向其他方法未排除）或 direction_wide（整个攻击方向被否定）\n"
                "未测试替代: [同方向下未测试的其他方法，留空表示全部测试过]\n\n"
                "示例:\n"
                "假设: ctf 用户可以通过硬链接替换 tfuser 的 state 文件\n"
                "否定证据: `ln /tmp/terraform.tfstate /tmp/evil.tfstate` -> Operation not permitted (sticky bit on /tmp)\n"
                "覆盖范围: method_only\n"
                "未测试替代: TF_PLUGIN_CACHE_DIR 覆盖、.tfstate.backup 替换、TF_DATA_DIR 环境变量注入",
                is_error=True,
            )

    source = args.get("source")
    if isinstance(source, str):
        source = source.strip()
        if source.startswith("{"):
            try:
                source = json.loads(source)
            except json.JSONDecodeError:
                source = {"note": source}
        else:
            source = {"note": source}
    if source is not None and not isinstance(source, dict):
        source = {"note": str(source)}

    safe_source = _sanitize_source(source or {})

    try:
        from chying_agent.runtime.context import get_current_challenge_code

        challenge_code = get_current_challenge_code()
    except Exception:
        challenge_code = None

    meta: Dict[str, Any] = {
        "status": status,
        "verification_method": verification_method,
        "next_action": next_action or None,
        "confidence": None,
        "source": safe_source,
        "challenge_code": challenge_code,
        "commands_and_results": commands_and_results or None,
        "paths_tried": paths_tried or None,
        "paths_not_tried": paths_not_tried or None,
        "blocked_assumption": blocked_assumption or None,
    }

    conf = args.get("confidence")
    if conf is not None:
        try:
            c = float(conf)
            meta["confidence"] = max(0.0, min(1.0, c))
        except Exception:
            meta["confidence"] = None

    # 1) DB
    try:
        from chying_agent.db import recorder

        recorder.upsert_memory_item(
            kind=kind, title=title, details=details,
            meta=meta, evidence=evidence,
        )
    except Exception as e:
        _logger.exception("record_key_finding failed")
        return _as_text_result(f"record_key_finding failed: {e}", is_error=True)

    # 2) findings.log（append-only 结构化条目）
    try:
        _append_key_finding_markdown(
            kind=kind, title=title, evidence=evidence,
            details=details, meta=meta,
        )
    except Exception:
        pass

    # 3) progress.md（结构化渲染视图）
    try:
        _sync_finding_to_progress(
            kind=kind, title=title, evidence=evidence,
            details=details, meta=meta,
        )
    except Exception:
        pass

    # 4) ACTIVE TARGET 置顶（仅 confirmed/exploited，verbatim evidence，保序显著性）
    if status in ("confirmed", "exploited") and verification_method != "inferred":
        try:
            _update_active_target(
                title=title,
                evidence=evidence,
                status=status,
                next_action=next_action or None,
            )
        except Exception:
            pass

    result_msg = f"OK: recorded {kind}/{title} (status={status}, verification={verification_method})"

    # dead_end 但未填写 blocked_assumption 时，附加提醒（非强制）
    if (kind == "dead_end" or status == "dead_end") and not blocked_assumption:
        result_msg += (
            "\n\nHint: Consider adding blocked_assumption to distinguish method failure "
            "from direction failure. Format:\n"
            "  假设: [what you assumed]\n"
            "  否定证据: [what disproved it]\n"
            "  覆盖范围: method_only / direction_wide\n"
            "  未测试替代: [untested alternatives in the same direction]"
        )

    return _as_text_result(result_msg)


# ==================== 工作目录工具 ====================


@tool(
    name="list_workdir",
    description="列出当前题目工作目录下的所有文件和基本题目信息",
    input_schema={},
)
async def list_workdir_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        from chying_agent.runtime.context import get_current_challenge_code
        challenge_code = get_current_challenge_code()
    except Exception:
        challenge_code = None

    work_dir = get_current_work_dir()
    if not work_dir:
        return _as_text_result("错误：无法获取工作目录", is_error=True)

    work_path = Path(work_dir)
    if not work_path.exists():
        return _as_text_result(f"错误：工作目录不存在 - {work_dir}", is_error=True)

    try:
        info = [
            f"题目: {challenge_code or '未知'}",
            f"工作目录: {work_dir}",
            "",
        ]

        files = []
        for item in sorted(work_path.iterdir()):
            if item.name.startswith("."):
                continue

            if item.is_file():
                size = item.stat().st_size
                if size < 1024:
                    size_str = f"{size} B"
                else:
                    size_str = f"{size // 1024} KB"
                files.append(f"  {item.name} ({size_str})")
            elif item.is_dir():
                count = len(list(item.iterdir()))
                files.append(f"  {item.name}/ ({count} files)")

        if files:
            info.extend(files)
        else:
            info.append("  (empty)")

        return _as_text_result("\n".join(info))

    except Exception as e:
        return _as_text_result(f"列出目录失败: {str(e)}", is_error=True)


# ==================== WSS Terminal 工具 ====================


@tool(
    name="wss_connect",
    description="管理 Web 终端 WebSocket 会话。"
    "传 url → 建立新连接（已有同 URL 的旧会话自动关闭）。未提供 cookie 时自动从缓存获取。"
    "传 session_id 不传 url → 关闭指定会话。",
    input_schema={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "WSS endpoint (e.g. wss://example.com/ws/shell)"},
            "session_id": {"type": "string", "description": "要关闭的 session_id（关闭模式：只传此参数）"},
            "cookie": {"type": "string", "description": "认证 Cookie 字符串 (e.g. session_id=xxx)"},
            "protocol": {
                "type": "string",
                "description": "协议类型: ttyd|wetty|gotty|k8s|generic|auto (默认 auto)",
                "default": "auto",
            },
            "origin": {
                "type": "string",
                "description": "Origin header (e.g. https://example.com)，用于通过 Origin 校验",
            },
            "extra_headers": {
                "type": "object",
                "description": "额外 HTTP headers (e.g. {\"Authorization\": \"Bearer xxx\", \"User-Agent\": \"...\"})",
                "additionalProperties": {"type": "string"},
            },
            "subprotocols": {
                "type": "array",
                "items": {"type": "string"},
                "description": "WebSocket subprotocols (e.g. [\"tty\"])",
            },
        },
    },
)
async def wss_connect_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    url = str(args.get("url", ""))
    session_id_to_close = str(args.get("session_id", ""))

    # 关闭模式：只传 session_id，不传 url
    if session_id_to_close and not url:
        manager = get_session_manager()
        status = await manager.close(session_id_to_close)
        return _as_text_result(f"WSS session {session_id_to_close}: {status}")

    err = _validate_non_empty(url, field="url")
    if err:
        return _as_text_result(err, is_error=True)

    cookie = str(args.get("cookie", ""))
    protocol = str(args.get("protocol", "auto"))
    origin = args.get("origin") or None
    extra_headers = args.get("extra_headers") or None
    subprotocols = args.get("subprotocols") or None

    # 容错：extra_headers 可能被序列化为 JSON 字符串
    if isinstance(extra_headers, str):
        try:
            extra_headers = json.loads(extra_headers)
        except json.JSONDecodeError:
            extra_headers = None

    # 无 cookie 时自动从缓存获取
    if not cookie:
        from chying_agent.claude_sdk import cookie_cache
        cached = cookie_cache.get_for_url(url)
        if cached:
            cookie = cached
            log_system_event("[WSS] 从 cookie 缓存自动获取 cookie")

    manager = get_session_manager()
    session_id, status, banner = await manager.create(
        url, cookie, protocol,
        origin=origin,
        extra_headers=extra_headers,
        subprotocols=subprotocols,
    )

    if status == "failed":
        is_auth_failure = any(
            kw in banner.lower()
            for kw in ("4001", "unauthorized", "forbidden", "403", "authentication")
        )
        if is_auth_failure:
            hint = (
                "WSS 连接被服务器拒绝（疑似认证失败，缺少有效 cookie）。\n"
                "Cookie 缓存中无此域名的 cookie。请手动获取后重试：\n"
                "1. evaluate_script(() => document.cookie) 获取 JS 可见 cookie\n"
                "2. 如为空（httpOnly），用 list_network_requests + get_network_request 提取 Cookie 请求头\n"
                "3. 用提取到的 cookie 重新调用 wss_connect(url=..., cookie=<cookie>)"
            )
        else:
            hint = (
                "提示：使用 Skill('wss-terminal') 从浏览器页面提取正确的参数"
                "（URL、cookie、protocol、subprotocol、origin）后重试。\n"
                "如果仍然失败，回退到 window.__wt 方式或 fill+press_key 方式。"
            )
        return _as_text_result(
            f"WSS 连接失败: {banner}\n{hint}",
            is_error=True,
        )

    banner_header = (
        f"WSS 连接成功\n"
        f"session_id: {session_id}\n"
        f"status: {status}\n\n"
        f"--- Banner ---\n"
    )

    if len(banner) > MAX_OUTPUT_LENGTH:
        _, summary = save_long_output(banner, "wss_banner")
        return _as_text_result(banner_header + summary)

    return _as_text_result(banner_header + banner)


@tool(
    name="wss_exec",
    description="在已连接的 WSS 终端会话中执行命令（1 次调用 = 1 条命令，自动清理输出）",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string", "description": "wss_connect 返回的 session_id"},
            "command": {"type": "string", "description": "要执行的 shell 命令"},
            "timeout": {"type": "integer", "description": "超时秒数 (默认 30)", "default": 30},
        },
        "required": ["session_id", "command"],
    },
)
async def wss_exec_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    session_id = str(args.get("session_id", ""))
    command = str(args.get("command", ""))
    timeout = int(args.get("timeout", 30))

    for field, val in [("session_id", session_id), ("command", command)]:
        err = _validate_non_empty(val, field=field)
        if err:
            return _as_text_result(err, is_error=True)

    manager = get_session_manager()
    try:
        session = manager.get(session_id)
    except ValueError as e:
        return _as_text_result(str(e), is_error=True)

    output, exit_hint, exit_code = await session.exec(command, timeout=timeout)

    if exit_hint == "session_dead":
        return _as_text_result(
            f"WSS session disconnected (session_id={session_id})\n"
            f"Partial output collected:\n{output}\n\n"
            f"Recovery steps:\n"
            f"1. Call wss_connect(session_id='{session_id}') to close, then wss_connect(url=...) to reconnect\n"
            f"2. Read progress.md Attack Tree and Current Phase to restore attack state\n"
            f"3. Resume your previous attack vector from where you left off — do NOT re-enumerate the environment",
            is_error=True,
        )

    is_error = exit_hint == "timeout" or (
        exit_code is not None and exit_code != 0
    )
    exit_code_text = str(exit_code) if exit_code is not None else "unknown"

    if len(output) > MAX_OUTPUT_LENGTH:
        cmd_prefix = command.split()[0].replace("/", "_") if command else "wss"
        _, summary = save_long_output(output, f"wss_{cmd_prefix}")
        return _as_text_result(
            f"exit_hint: {exit_hint}\n"
            f"exit_code: {exit_code_text}\n\n{summary}",
            is_error=is_error,
        )

    return _as_text_result(
        f"exit_hint: {exit_hint}\n"
        f"exit_code: {exit_code_text}\n\n{output}",
        is_error=is_error,
    )


@tool(
    name="wss_close",
    description="关闭 WSS 终端会话",
    input_schema={
        "type": "object",
        "properties": {
            "session_id": {"type": "string", "description": "要关闭的 session_id"},
        },
        "required": ["session_id"],
    },
)
async def wss_close_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    session_id = str(args.get("session_id", ""))
    err = _validate_non_empty(session_id, field="session_id")
    if err:
        return _as_text_result(err, is_error=True)

    manager = get_session_manager()
    status = await manager.close(session_id)
    return _as_text_result(f"WSS session {session_id}: {status}")


@tool(
    name="kb_search",
    description="搜索预编译的技术知识 wiki，获取攻击技术、攻击面、常见利用步骤、代码片段、常见坑和变体。"
    "当前仅检索 `knowledge/wiki/techniques/**/*.md` 下的编译页面，不搜索 `knowledge/raw` 原始资料。"
    "底层是 frontmatter tags/triggers 的关键词匹配与类别优先匹配，不是全量语义检索。"
    "在以下场景使用："
    "1) 已识别出具体产品、框架、中间件或控制台（如 `Dify`、`JumpServer`、`Nacos`、`GitLab`）后，检索其已知攻击面、历史 CVE 利用思路或相关技术页；"
    "2) 已判断出技术原语（如 `jwt`、`java deserialization`、`ssti`、`ssrf`、`oauth`）后，检索对应步骤、代码模板和常见坑；"
    "3) 卡住、反思或发现新线索（报错、版本、接口路径、组件名）时，换更精确的技术关键词重新检索；"
    "4) 需要把题目名、业务语义词映射到通用攻击面时，用“产品名/组件名 + 漏洞类型/CVE/版本”的方式查询。"
    "不适用于搜索原始资料、泛业务自然语言长描述，或没有技术关键词的模糊问题。",
    input_schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "检索关键词。优先使用技术术语、产品名、组件名、版本号、CVE 或协议名，如 'java deserialization xstream', 'Dify auth bypass', 'Langflow CVE-2025-3248', 'ssrf metadata', 'oauth redirect_uri'。避免只输入模糊业务词或整段自然语言描述。",
            },
            "category": {
                "type": "string",
                "description": "题目类别。会优先检索同类别技术页面；若同类别无命中，再回退全库（web/cloud/pwn/misc/crypto/reverse/forensics）。当你已经确定题目大类时建议填写，可减少跨类误命中。",
                "default": "",
            },
            "top_k": {
                "type": "integer",
                "description": "返回候选文档数量（默认 5）",
                "default": 5,
            },
        },
        "required": ["query"],
    },
)
async def kb_search_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    query = str(args.get("query", "")).strip()
    category = str(args.get("category", "")).strip()
    top_k = int(args.get("top_k", 5))

    if not query:
        return _as_text_result("[kb_search] query 不能为空", is_error=True)

    try:
        from chying_agent.rag import query_kb
        from chying_agent.rag.client import format_kb_results_for_prompt

        candidates = await query_kb(
            description=query,
            category=category,
            top_k=top_k,
        )

        if candidates:
            log_kb_event(
                "知识检索完成",
                doc_count=len(candidates),
                source="Orchestrator",
            )

        if not candidates:
            return _as_text_result(
                f"[kb_search] 未找到与 '{query}' 相关的知识文档。"
                "建议：换用不同的技术术语重新检索。"
            )

        formatted = format_kb_results_for_prompt(candidates)
        if formatted and len(formatted) > MAX_OUTPUT_LENGTH:
            work_dir = get_current_work_dir()
            if work_dir:
                saved_path, _summary = save_long_output(
                    formatted, "kb_search_result", work_dir
                )
                summary = f"[kb_search] 检索到 {len(candidates)} 个技术页面，结果已保存到 {saved_path}\n\n"
                summary += "\n".join(
                    f"- [{c.get('score', 0):.0f}] {c.get('id', '')}"
                    for c in candidates
                )
                return _as_text_result(summary)

        return _as_text_result(formatted or "(无结果)")

    except Exception as e:
        _logger.warning("[kb_search] 查询失败: %s", e)
        return _as_text_result(
            f"[kb_search] 知识库查询失败: {e}。",
            is_error=True,
        )


_MCP_SERVER_NAME = "chying"


# ==================== Hint 工具 (MCP 比赛模式) ====================


@tool(
    name="view_hint",
    description="查看当前题目的提示信息。会扣除该题总分的一定比例！"
    "仅在你已经尝试了多种方法仍无法突破时使用。",
    input_schema={},
)
async def view_hint_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    from chying_agent.runtime.context import get_hint_callback

    callback = get_hint_callback()
    if callback is None:
        return _as_text_result("当前环境不支持自动获取 hint 功能，请自己探索（非比赛模式）")
    try:
        hint_text = await callback()
        try:
            _append_hint_markdown(hint_text)
            from chying_agent.claude_sdk.hooks import _sync_hint_summary_to_progress

            _sync_hint_summary_to_progress(hint_text)
        except Exception as e:
            log_system_event(f"[Hint] hint.md 追加失败: {e}", level=logging.WARNING)
        return _as_text_result(f"[Hint]\n{hint_text}")
    except Exception as e:
        return _as_text_result(f"获取 hint 失败: {e}", is_error=True)


# ==================== Submit Flag 工具 (MCP 比赛模式) ====================


@tool(
    name="submit_flag",
    description=(
        "立即向 CTF 平台提交一个 flag。"
        "在多 flag 题目中，每发现一个 flag 后必须立刻调用此工具提交，"
        "不要等到所有 flag 都找到后再提交，以防超时导致 flag 丢失。"
    ),
    input_schema={
        "type": "object",
        "properties": {
            "flag": {
                "type": "string",
                "description": "要提交的 flag，例如 flag{abc123...}",
            },
        },
        "required": ["flag"],
    },
)
async def submit_flag_tool(args: Dict[str, Any]) -> Dict[str, Any]:
    from chying_agent.runtime.context import get_submit_flag_callback

    flag = (args.get("flag") or "").strip()
    if not flag:
        return _as_text_result("submit_flag: flag 参数不能为空", is_error=True)

    callback = get_submit_flag_callback()
    if callback is None:
        # 非比赛模式或回调未注入——记录但不报错，避免阻断 agent 流程
        log_system_event(f"[submit_flag] 非比赛模式，跳过提交: {flag}")
        return _as_text_result(
            f"[submit_flag] 当前环境不支持自动提交（非比赛模式），flag 已记录: {flag}"
        )

    try:
        ok, message = await callback(flag)
        status = "正确 ✅" if ok else "错误 ❌"
        log_system_event(f"[submit_flag] {status}: {flag} — {message}")

        # 同步记录到 findings.log
        try:
            _record_submitted_flag(flag, ok, message)
        except Exception as e:
            log_system_event(f"[submit_flag] 持久化记录失败: {e}", level=logging.WARNING)

        return _as_text_result(
            f"[submit_flag] {status}\nFlag: {flag}\n平台回应: {message}"
        )
    except Exception as e:
        log_system_event(f"[submit_flag] 提交异常: {e}", level=logging.WARNING)
        return _as_text_result(f"[submit_flag] 提交失败: {e}", is_error=True)


# 所有内置 MCP 工具（集中定义，单一事实源）
# browser_operate 和 reverse_analyze 已迁移为 Task 子代理（MCP Visibility 机制）
_BASE_CHYING_TOOLS = [
    exec_tool,
    record_key_finding_tool,
    wss_connect_tool,
    wss_exec_tool,
    view_hint_tool,
    submit_flag_tool,
]


def _get_active_tools():
    """返回当前启用的 MCP 工具列表。知识库未启用时不暴露 kb_search 工具。"""
    from ..config import RAGConfig
    tools = list(_BASE_CHYING_TOOLS)
    if RAGConfig.from_env().enabled:
        tools.insert(-2, kb_search_tool)  # 插在 view_hint 前面，submit_flag 之前
    return tools


def get_chying_mcp_tool_names() -> list[str]:
    """返回所有内置 MCP 工具的完整名称（mcp__{server}__{tool}），供 ALLOWED_TOOLS 使用。"""
    return [f"mcp__{_MCP_SERVER_NAME}__{t.name}" for t in _get_active_tools()]


def get_chying_sdk_mcp_servers() -> Dict[str, Dict[str, Any]]:
    """返回可直接塞进 `ClaudeAgentOptions.mcp_servers` 的配置字典。"""
    server = create_sdk_mcp_server(
        name="chying-tools",
        version="1.0.0",
        tools=_get_active_tools(),
    )
    return {_MCP_SERVER_NAME: server}
