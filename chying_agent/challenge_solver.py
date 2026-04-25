"""
单题解题逻辑模块
================

负责单个题目的解题流程：
- 自动侦察
- Agent 执行
- 结果处理
- Transcript 归档

使用 ExecutionContext 自动管理 DB 记录生命周期。
"""

import asyncio
import contextlib
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse

from chying_agent.common import log_system_event, set_challenge_context, clear_challenge_context
from chying_agent.db import ExecutionContext
from chying_agent.runtime.context import (
    set_current_challenge_code,
    clear_current_challenge_code,
    set_current_work_dir,
    get_current_work_dir,
)
from chying_agent.utils.flag_validator import extract_flag_from_text
from chying_agent.utils.path_utils import convert_docker_path_to_host
from chying_agent.claude_sdk.wss_terminal_client import cleanup_session_manager
from chying_agent.brain_agent.progress_compiler import run_progress_compiler

if TYPE_CHECKING:
    from chying_agent.task_manager import ChallengeStats


# ==================== 配置 ====================

# 单题超时（秒）
DEFAULT_SINGLE_TASK_TIMEOUT = int(os.getenv("SINGLE_TASK_TIMEOUT", "2400"))


# ==================== 辅助函数 ====================


def _make_result(
    code: str,
    flag: Optional[str] = None,
    score: int = 0,
    attempts: int = 0,
    success: bool = False,
    **extras,
) -> Dict:
    """构建统一的结果字典"""
    return {
        "code": code,
        "flag": flag,
        "score": score,
        "attempts": attempts,
        "success": success,
        **extras,
    }


def _extract_flag(text: str) -> Optional[str]:
    """从文本中提取 flag"""
    if not text:
        return None
    flags = extract_flag_from_text(text)
    return flags[0] if flags else None


def _redact_history_flags(text: str) -> tuple[str, bool]:
    """标注历史上下文中的 FLAG（新实例 flag 会变，但保留路径信息方便复现）。

    不再脱敏 flag 值——因为 flag 是动态生成的（新实例新 flag），保留完整的
    攻击路径和 flag 位置信息反而能帮助 agent 快速复现。仅在 flag 后追加标注。
    """
    if not text:
        return text, False

    annotated = text
    found = False
    for flag in extract_flag_from_text(text):
        annotated = annotated.replace(
            flag, f"{flag} ← [历史FLAG，新实例已变化，用相同路径重新读取即可]"
        )
        found = True
    return annotated, found


def _split_execution_summary_sections(summary_content: str) -> tuple[list[str], list[str], list[str]]:
    """按 success / failed / other 拆分 execution_summary.md 里的尝试记录。"""
    sections: list[str] = []
    current: list[str] = []

    for line in summary_content.splitlines():
        if line.startswith("## Attempt #"):
            if current:
                section = "\n".join(current).strip()
                if section:
                    sections.append(section)
            current = [line]
            continue

        if current or line.strip():
            current.append(line)

    if current:
        section = "\n".join(current).strip()
        if section:
            sections.append(section)

    success_sections: list[str] = []
    failed_sections: list[str] = []
    other_sections: list[str] = []

    for section in sections:
        if re.search(r"^- Status:\s*success\b", section, flags=re.MULTILINE | re.IGNORECASE):
            success_sections.append(section)
        elif re.search(r"^- Status:\s*\w+\b", section, flags=re.MULTILINE | re.IGNORECASE):
            failed_sections.append(section)
        else:
            other_sections.append(section)

    return success_sections, failed_sections, other_sections


def _is_truthy(val) -> bool:
    """判断 structured data 中的布尔字段是否为真（兼容 LLM 返回的字符串）"""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "yes", "1")
    return bool(val)


_CLOUD_CATEGORY_HINTS = (
    "cloudsecuritychampionship",
    "cloud security championship",
    "aws",
    "arn:aws",
    "amazon s3",
    "s3",
    "bucket",
    "lambda",
    "sns",
    "sqs",
    "iam",
    "cloudfront",
    "api gateway",
    "api-gateway",
    "dynamodb",
    "azure",
    "gcp",
    "kubernetes",
    "eks",
    "ecs",
    "ec2",
)


def _collect_category_hint_text(challenge: Dict) -> str:
    """汇总可用于类别预判的文本线索。"""
    parts: list[str] = []
    for key in ("challenge_code", "_challenge_name", "_prompt", "_hint"):
        value = challenge.get(key)
        if value:
            parts.append(str(value))

    target_info = challenge.get("target_info", {})
    urls = challenge.get("_target_urls") or target_info.get("urls") or []
    for url in urls:
        if url:
            parts.append(str(url))

    target_ip = target_info.get("ip")
    if target_ip:
        parts.append(str(target_ip))

    return "\n".join(parts)


def _looks_like_cloud_challenge(text: str) -> bool:
    """根据关键词判断当前题目是否更像云安全题。"""
    lower = text.lower()
    return any(keyword in lower for keyword in _CLOUD_CATEGORY_HINTS)


def _probe_category_from_target(challenge: Dict) -> Optional[str]:
    """对首个 URL 做轻量探测，补充类别判断。"""
    target_info = challenge.get("target_info", {})
    target_urls = challenge.get("_target_urls") or target_info.get("urls") or []
    if not target_urls:
        return None

    first_url = str(target_urls[0]).strip()
    if not first_url.startswith(("http://", "https://")):
        return None

    parsed = urlparse(first_url)
    host = parsed.hostname or target_info.get("ip")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return None

    try:
        from chying_agent.utils.recon import auto_recon_web_target

        recon = auto_recon_web_target(host, port, timeout=10, url=first_url)
    except Exception as e:
        log_system_event(f"[分类预判] 页面探测失败: {e}", level=logging.DEBUG)
        return None

    if not recon.get("success"):
        return None

    headers = recon.get("headers") or {}
    header_lines = [f"{k}: {v}" for k, v in headers.items()]
    probe_text = "\n".join(
        part
        for part in (
            recon.get("title", ""),
            "\n".join(header_lines),
            str(recon.get("html_content", ""))[:4000],
        )
        if part
    )
    if _looks_like_cloud_challenge(probe_text):
        return "cloud"
    return None


def normalize_challenge_category(
    challenge: Dict,
    allow_probe: bool = False,
    fallback_to_web: bool = True,
) -> str:
    """在进入主流程前预判题目类别，并写回 challenge。"""
    current = str(challenge.get("category") or "").strip().lower()

    if current and current not in {"unknown", "web"}:
        return current

    mode = str(challenge.get("_mode") or "").strip().lower()
    if mode == "ctf-web":
        challenge["category"] = "web"
        return "web"

    hint_text = _collect_category_hint_text(challenge)
    resolved = "cloud" if _looks_like_cloud_challenge(hint_text) else None
    if resolved is None and allow_probe:
        resolved = _probe_category_from_target(challenge)

    if resolved is None:
        if current and current != "unknown":
            resolved = current
        elif fallback_to_web:
            resolved = "web"
        else:
            resolved = "unknown"

    if resolved != current:
        log_system_event(
            "[分类预判] 已修正题目类别",
            {
                "challenge_code": challenge.get("challenge_code", ""),
                "from": current or "unknown",
                "to": resolved,
            },
        )
    challenge["category"] = resolved
    return resolved


def _setup_work_dir(challenge: Dict, challenge_code: str) -> None:
    """设置题目工作目录（统一到 agent-work/ctf/{Category}/ 下）"""
    from chying_agent.utils.path_utils import get_host_agent_work_dir

    host_agent_work = get_host_agent_work_dir()
    target_info = challenge.get("target_info", {})
    challenge_path = target_info.get("path")

    if challenge_path:
        host_path = convert_docker_path_to_host(challenge_path)
        work_dir = Path(host_path)
    else:
        # 统一到 agent-work/ctf/{Category}/ 下（与 CTF 模式一致）
        category = str(challenge.get("category") or "unknown").capitalize()
        work_dir = host_agent_work / "ctf" / category / challenge_code

    work_dir.mkdir(parents=True, exist_ok=True)

    set_current_work_dir(work_dir)


def _extract_compiler_sections(
    compiled_prompt: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """从 PromptCompiler 输出中提取动态段落和类别修正提示。"""
    if not compiled_prompt:
        return compiled_prompt, None

    corrected_category = None
    category_match = re.search(
        r"<resolved_category>\s*(\w+)\s*</resolved_category>",
        compiled_prompt,
        flags=re.IGNORECASE,
    )
    if category_match:
        corrected_category = category_match.group(1).strip().lower()

    sections = compiled_prompt
    sections = re.sub(
        r"<compiler_hints>.*?</compiler_hints>\s*",
        "",
        sections,
        flags=re.IGNORECASE | re.DOTALL,
    )
    # 向后兼容：即使模型偶尔输出旧的 metadata block，也丢弃并由代码重新注入。
    sections = re.sub(
        r"<challenge_metadata>.*?</challenge_metadata>\s*",
        "",
        sections,
        flags=re.IGNORECASE | re.DOTALL,
    )
    sections = re.sub(
        r"<challenge_metadata_raw>.*?</challenge_metadata_raw>\s*",
        "",
        sections,
        flags=re.IGNORECASE | re.DOTALL,
    )

    return sections.strip(), corrected_category


def _build_compiled_context(
    *,
    challenge_code: str,
    category: str,
    mode: str,
    points: int,
    target_urls: list[str],
    target_host_ports: str,
    work_dir: Optional[Path],
    auth_env_keys: list[str],
    user_prompt: str,
    hint: str,
    compiled_sections: str,
) -> str:
    """由代码拼装最终 prompt，确保 metadata 不被 LLM 丢失。"""
    metadata_lines = [
        f"challenge_code: {challenge_code}",
        f"category: {category}",
        f"mode: {mode}",
        f"points: {points}",
    ]
    if target_urls:
        metadata_lines.append(f"target_urls: {', '.join(target_urls)}")
    if target_host_ports:
        metadata_lines.append(f"target_host_ports: {target_host_ports}")
    if work_dir:
        metadata_lines.append(f"work_dir: {work_dir}")
    if auth_env_keys:
        metadata_lines.append(f"auth_env_keys: {', '.join(auth_env_keys)}")

    context_parts = [
        "<challenge_metadata>\n" + "\n".join(metadata_lines) + "\n</challenge_metadata>"
    ]

    if hint.strip():
        context_parts.append(f"<challenge_hint>\n{hint.strip()}\n</challenge_hint>")

    if user_prompt.strip():
        context_parts.append(f"<challenge_brief>\n{user_prompt.strip()}\n</challenge_brief>")

    if compiled_sections.strip():
        context_parts.append(compiled_sections.strip())

    return "\n\n".join(context_parts)


def _do_web_recon(
    target_ip: str,
    target_ports: list,
    challenge_code: str,
    recon_parts: list,
    target_urls: Optional[list] = None,
) -> tuple[int, int]:
    """执行 Web 目标自动侦察，结果追加到 recon_parts"""
    from chying_agent.utils.recon import auto_recon_web_target, format_recon_result_for_llm

    # 构建侦察目标列表
    recon_targets: list[tuple[str, int, str | None]] = []
    if target_urls:
        for url in target_urls:
            parsed = urlparse(url)
            host = parsed.hostname or target_ip
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            recon_targets.append((host, port, url))
    else:
        ports_to_scan = target_ports if isinstance(target_ports, list) else [target_ports]
        for port in ports_to_scan:
            recon_targets.append((target_ip, port, None))

    reachable_count = 0
    total_count = len(recon_targets)

    for host, port, url in recon_targets:
        try:
            recon_result = auto_recon_web_target(host, port, timeout=30, url=url)
            recon_summary = format_recon_result_for_llm(recon_result)
            label = url or f"{host}:{port}"
            recon_parts.append(f"### {label}\n{recon_summary}")
            if recon_result.get("success"):
                reachable_count += 1
            log_system_event(
                f"[自动侦察] {label} 完成",
                {"status_code": recon_result.get("status_code")},
            )
        except Exception as e:
            label = url or f"{host}:{port}"
            log_system_event(f"[自动侦察] {label} 失败: {e}", level=logging.WARNING)
            recon_parts.append(f"### {label}\n侦察失败: {e}")

    # httpx 指纹识别（在 Docker 容器内执行）
    httpx_urls = [url for _, _, url in recon_targets if url]
    if not httpx_urls:
        httpx_urls = [f"http://{host}:{port}" for host, port, _ in recon_targets]
    if httpx_urls:
        httpx_result = _run_httpx_fingerprint(httpx_urls)
        if httpx_result:
            recon_parts.append(httpx_result)

    # 可达性摘要：追加到 recon_parts 供快速失败判断使用
    if total_count > 0 and reachable_count == 0:
        recon_parts.append(
            f"### ⚠️ 可达性警告\n"
            f"所有 {total_count} 个侦察目标均无法访问（连接拒绝/超时/连接失败）。"
            f"目标服务可能未启动或网络不可达。"
        )
        log_system_event(
            f"[自动侦察] 全部目标不可达",
            {"total": total_count, "reachable": reachable_count},
            level=logging.WARNING,
        )

    return reachable_count, total_count


def _run_httpx_fingerprint(urls: list[str]) -> str | None:
    """在 Docker 容器内运行 httpx 指纹识别，返回格式化结果或 None"""
    try:
        from chying_agent.runtime.singleton import get_config_manager
        executor = get_config_manager().executor
        url_list = " ".join(urls)
        result = executor.execute(
            f"echo '{url_list}' | tr ' ' '\\n' | httpx -silent -title -tech-detect -status-code -content-length -server -follow-redirects -timeout 15",
            timeout=30,
            caller="httpx_fingerprint",
        )
        output = result.stdout.strip() if result.stdout else ""
        if not output:
            log_system_event("[httpx] 无输出")
            return None
        log_system_event(
            f"[httpx] 指纹识别完成",
            {"lines": len(output.splitlines()), "output_preview": output[:200]},
        )
        return f"### httpx 指纹识别\n```\n{output}\n```"
    except Exception as e:
        log_system_event(f"[httpx] 指纹识别失败: {e}", level=logging.WARNING)
        return None


def _build_scene_creation_instruction(
    platform_url: str,
    challenge_name: str,
    challenge_id: str,
) -> str:
    """构建场景创建指令，注入到 orchestrator context 开头。

    当 scraper 阶段未启动场景（_needs_scene=True）时调用，
    指导 orchestrator 在开始攻击前先通过浏览器创建靶机场景。
    """
    return (
        "## [前置任务] 创建靶机场景\n\n"
        "本题目尚未启动靶机场景，你需要在开始攻击之前先创建场景获取靶机地址。\n\n"
        "**操作步骤**:\n"
        f"1. 使用 Chrome DevTools MCP 的 take_snapshot 查看当前浏览器页面\n"
        f"2. 导航到 CTF 平台: {platform_url}\n"
        f"3. 找到题目 '{challenge_name}' (ID: {challenge_id})，点击打开详情\n"
        f"4. 点击 '获取在线场景' / 'Start Instance' / '启动靶机' 按钮\n"
        f"5. 如果弹出确认对话框（如 '会关闭已有场景'），点击确认\n"
        f"6. 等待场景启动，从页面中提取靶机地址 (通常是 http://IP:PORT 格式)\n"
        f"7. 使用获取到的靶机地址作为攻击目标，开始解题\n\n"
        "**注意**: 每个平台账号同时只能有一个活跃场景，"
        "系统已确保你是当前唯一需要场景的任务，不会与其他任务冲突。\n"
    )


def _build_file_info(category: str, target_info: Dict) -> Optional[str]:
    """构建非 Web 题目的文件信息字符串"""
    challenge_path = target_info.get("path", "")
    files = target_info.get("files", [])
    files_metadata = target_info.get("files_metadata", [])

    if not (challenge_path and files):
        return None

    if files_metadata:
        file_list = "\n".join([
            f"  - `{fm['name']}` ({fm['size_human']}) - {fm.get('file_type', 'unknown')}"
            for fm in files_metadata
        ])
    else:
        file_list = "\n".join([f"  - `{f}`" for f in files])

    return f"""**题目信息**

**类型**: {category.upper()}
**目录**: {challenge_path}
**文件列表**:
{file_list}

**分析建议**:
- 使用 `mcp__chying__exec` 运行分析命令（language=python 执行 Python 脚本）
- ⚠️ **不要直接读取二进制文件**
"""


def _extract_last_reflection_conclusions(content: str) -> Optional[str]:
    """从 reflection_history.md 中提取最后一条反思报告的关键结论。

    提取以下高价值段落（如果存在）：
    - Stagnation Diagnosis（停滞诊断）
    - Abandoned Progress Lines（被遗弃的进展线，高价值线索）
    - Repeated Patterns (ABANDON)（已证明失败的方向）
    - Recommended Todo Update（推荐的下一步计划）

    Args:
        content: reflection_history.md 的完整内容

    Returns:
        提取的结论文本，如果没有有效内容返回 None
    """
    # 找到最后一个 "## System Reflection Report" 或 "## Reflection #"
    sections = content.split("## System Reflection Report")
    if len(sections) < 2:
        # 尝试按 "## Reflection #" 分割
        sections = content.split("## Reflection #")
    if len(sections) < 2:
        return None

    last_report = sections[-1]

    # 提取关键段落
    target_headings = [
        "### Stagnation Diagnosis",
        "### Abandoned Progress Lines",
        "### Repeated Patterns",
        "### Recommended Todo Update",
        "### Key Findings Review",
    ]

    extracted_parts = []
    for heading in target_headings:
        idx = last_report.find(heading)
        if idx < 0:
            continue
        # 找到这个段落的结束位置（下一个 ### 或 --- 或文档末尾）
        remaining = last_report[idx:]
        end_markers = ["\n### ", "\n---"]
        end_idx = len(remaining)
        for marker in end_markers:
            # 跳过自身标题行，从第二行开始搜索
            first_newline = remaining.find("\n")
            if first_newline < 0:
                continue
            pos = remaining.find(marker, first_newline + 1)
            if 0 < pos < end_idx:
                end_idx = pos

        section_text = remaining[:end_idx].strip()
        if section_text:
            extracted_parts.append(section_text)

    if not extracted_parts:
        return None

    return "\n\n".join(extracted_parts)


def _is_solved_check(result) -> bool:
    """检查 orchestration result 是否已解出。"""
    if not result or not result.structured_data:
        return False
    sd = result.structured_data
    if not isinstance(sd, dict):
        return False
    solved = sd.get("solved")
    if solved is None:
        solved = sd.get("success")
    return bool(solved)


async def _run_branch_exploration(
    vectors: List[Dict],
    base_context: str,
    create_orchestrator,
    work_dir: Optional[Path],
) -> Optional["ResponseStreamResult"]:
    """按攻击向量顺序启动分支探索。

    为每个向量创建新的 Orchestrator 实例，注入专攻该向量的 context。
    第一个解出即返回。
    """
    from chying_agent.claude_sdk.reflection import extract_dead_ends

    dead_ends = extract_dead_ends(work_dir) if work_dir else []
    dead_end_text = "\n".join(f"- {d}" for d in dead_ends) if dead_ends else "(none)"

    MAX_BRANCHES = 3
    for i, vector in enumerate(vectors[:MAX_BRANCHES]):
        name = vector.get("name", f"Vector {i + 1}")
        desc = vector.get("description", "")
        priority = vector.get("priority", "medium")

        log_system_event(
            f"[Branch] 启动分支 {i + 1}/{min(len(vectors), MAX_BRANCHES)}: {name} (priority={priority})",
        )

        branch_context = (
            f"## Branch Exploration -- Focus: {name}\n\n"
            f"侦察阶段已完成。你现在需要专注探索以下攻击向量:\n\n"
            f"### 目标攻击向量\n"
            f"**{name}** (priority: {priority})\n"
            f"{desc}\n\n"
            f"### 已确认的失败方向 (DO NOT RETRY)\n\n{dead_end_text}\n\n"
            f"### 要求\n"
            f"1. 专注于上述攻击向量，深入利用\n"
            f"2. 不要切换到其他方向（系统会单独探索）\n"
            f"3. 阅读 progress.md 和 findings.log 获取完整侦察结果\n\n"
            f"---\n\n"
            + base_context
        )

        branch_orchestrator = create_orchestrator()
        try:
            branch_result = await branch_orchestrator.run(context=branch_context)
            if _is_solved_check(branch_result):
                log_system_event(f"[Branch] 分支 {name} 成功解出")
                return branch_result
            log_system_event(f"[Branch] 分支 {name} 未解出，尝试下一个")
        except Exception as e:
            log_system_event(
                f"[Branch] 分支 {name} 异常: {e}",
                level=logging.WARNING,
            )
        finally:
            try:
                await branch_orchestrator.reset_persistent_session()
            except Exception:
                pass

    return None


def _build_fresh_session_context(
    base_context: str,
    work_dir: Optional[Path],
) -> str:
    """为新会话构建包含前一会话知识的 context。

    从 progress.md 和 findings.log 提取 dead ends 和有效发现，
    构建"接手工作"的 context，明确禁止已失败方向。
    """
    if not work_dir:
        return base_context

    from chying_agent.claude_sdk.reflection import extract_dead_ends, extract_prior_findings

    dead_ends = extract_dead_ends(work_dir)
    findings = extract_prior_findings(work_dir)

    dead_end_text = "\n".join(f"- {d}" for d in dead_ends) if dead_ends else "(none)"
    findings_text = "\n".join(f"- {f}" for f in findings) if findings else "(none)"

    # 提取 findings.log 中标记为 UNVERIFIED-INFERENCE 的 paths_not_tried
    untested_text = "(none)"
    if work_dir:
        findings_file = work_dir / "findings.log"
        if findings_file.exists():
            try:
                import re as _re
                content = findings_file.read_text(encoding="utf-8")
                untested_items = []
                blocks = _re.split(r"(?=^### )", content, flags=_re.MULTILINE)
                for block in blocks:
                    if "paths_not_tried" in block:
                        pnt_match = _re.search(
                            r"\*\*paths_not_tried\*\*.*?:\n(.*?)(?=\n\*\*|\n---|\Z)",
                            block,
                            _re.DOTALL,
                        )
                        if pnt_match:
                            for line in pnt_match.group(1).strip().split("\n"):
                                line = line.strip()
                                if line and line not in untested_items:
                                    untested_items.append(line)
                if untested_items:
                    untested_text = "\n".join(f"- {item}" for item in untested_items)
            except Exception:
                pass

    return (
        "## Session Rotation -- Fresh Start\n\n"
        "前一个会话在探索过程中陷入停滞，你现在接手继续工作。\n\n"
        f"### 已确认的失败方向 (DO NOT RETRY)\n\n{dead_end_text}\n\n"
        f"### 已确认的发现 (可继续深入)\n\n{findings_text}\n\n"
        f"### 上次未尝试的方向 (PRIORITY: TRY THESE FIRST)\n\n{untested_text}\n\n"
        "### 要求\n"
        "1. 上述失败方向已经验证无效，不要以任何变体重试\n"
        "2. **优先尝试'上次未尝试的方向'**——这些是上次 agent 想到但没来得及执行的路径\n"
        "3. 利用已有发现组合新的攻击链\n"
        "4. 阅读 progress.md 和 findings.log 获取完整上下文\n\n"
        "---\n\n"
        + base_context
    )


async def _build_fresh_session_context_with_compiler(
    base_context: str,
    work_dir: Optional[Path],
    config,
) -> str:
    """跨 session rotation 时的新会话 context 构建，优先使用 ProgressCompiler 产出。

    注意：这是 Session Rotation 场景（整个 CLI session 重建），
    不同于同 session 内 compact 恢复（由 base.py 的 hook 机制处理）。

    流程：
    1. 启动 ProgressCompiler（最多等待 90s）
    2. 若成功：使用 compact_handoff.md 替代手工拼接的 fresh context
    3. 若失败/超时：静默降级到 _build_fresh_session_context() 旧逻辑

    Args:
        base_context: 原始题目 context（含 compiled sections 或 fallback context）
        work_dir: 题目工作目录
        config: 配置对象（用于提取 model/api_key 等参数，暂未用，预留扩展）

    Returns:
        注入了进度摘要的新会话 context 字符串
    """
    if not work_dir:
        return _build_fresh_session_context(base_context, work_dir)

    # 获取当前题目的系统日志文件路径，传给 ProgressCompiler
    try:
        from chying_agent.claude_sdk.reflection import get_current_log_file_path
        log_file_path: Optional[str] = get_current_log_file_path()
    except Exception:
        log_file_path = None

    # 运行 ProgressCompiler（带超时保护，失败返回 None）
    handoff_path = await run_progress_compiler(work_dir, log_file_path=log_file_path)

    if handoff_path and handoff_path.exists():
        try:
            handoff_content = handoff_path.read_text(encoding="utf-8").strip()
            if len(handoff_content) > 100:
                # ProgressCompiler 成功：用 handoff 替代手工拼接
                # base_context 仍然追加在末尾，保留原始题目背景
                log_system_event(
                    "[Session Rotation] ProgressCompiler handoff 注入成功",
                    {"handoff_bytes": len(handoff_content)},
                )
                return (
                    "## Session Rotation — Handoff from Previous Session\n\n"
                    "The previous session exhausted its context. "
                    "The following handoff was compiled by analyzing all raw logs.\n\n"
                    f"{handoff_content}\n\n"
                    "---\n\n"
                    + base_context
                )
        except Exception as e:
            log_system_event(
                f"[Session Rotation] handoff 读取失败，降级: {e}",
                level=logging.WARNING,
            )

    # Fallback：ProgressCompiler 失败时使用旧的手工拼接逻辑
    log_system_event("[Session Rotation] 降级到旧 fresh context 构建")
    return _build_fresh_session_context(base_context, work_dir)


def _build_prior_knowledge(
    work_dir: Path,
) -> Optional[str]:
    """从工作目录文件构建历史知识摘要

    检测上次执行留下的文件（execution_summary.md、findings.log、
    hint.md、reflection_history.md），提取关键信息注入新会话，避免重复劳动。

    如果存在 retry_handoff.md（由 RetryHandoffCompiler 生成的精炼续作报告），
    则直接使用它代替原始文件读取，大幅减少上下文消耗。

    Args:
        work_dir: 题目工作目录

    Returns:
        摘要字符串，如果没有历史信息则返回 None
    """
    # --- 优先使用 RetryHandoffCompiler 生成的精炼报告 ---
    handoff_file = work_dir / "retry_handoff.md"
    if handoff_file.exists():
        try:
            content = handoff_file.read_text(encoding="utf-8").strip()
            if content and len(content) > 100:
                log_system_event(
                    f"[历史知识] 使用 retry_handoff.md ({len(content)} chars)",
                )
                # 附加 hint.md（如果存在且未被 handoff 包含）
                hint_file = work_dir / "hint.md"
                hint_section = ""
                if hint_file.exists():
                    try:
                        hint_content = hint_file.read_text(encoding="utf-8").strip()
                        if hint_content:
                            hint_section = (
                                "\n\n### Hints Used (hint.md)\n\n" + hint_content
                            )
                    except Exception:
                        pass
                return (
                    "## Retry Handoff Report (generated by Retry Handoff Compiler)\n\n"
                    "The following report contains full attack chain reproduction steps. "
                    "Target IPs are replaced with TARGET_IP placeholders — "
                    "substitute with the current instance's actual IP. "
                    "Reproduce verified findings first, then continue from the Current Blocker section.\n\n"
                    + content + hint_section
                )
        except Exception as e:
            log_system_event(
                f"[历史知识] retry_handoff.md 读取失败: {e}",
                level=logging.WARNING,
            )

    parts: List[str] = []
    has_success_history = False
    has_failure_history = False

    # --- 1. 从 execution_summary.md 提取历史执行记录 ---
    summary_file = work_dir / "dumps" / "execution_summary.md"
    if summary_file.exists():
        try:
            summary_content = summary_file.read_text(encoding="utf-8").strip()
            if summary_content:
                sanitized_summary, _ = _redact_history_flags(summary_content)
                success_sections, failed_sections, other_sections = _split_execution_summary_sections(
                    sanitized_summary
                )

                if success_sections:
                    has_success_history = True
                    parts.append(
                        "### 历史已验证攻击路径（来自旧实例/旧会话）\n\n"
                        "以下成功记录包含完整的攻击路径和 flag 位置。"
                        "新实例 FLAG 已变化，但攻击路径相同——直接复现路径并重新读取 flag 即可。\n\n"
                        + "\n\n".join(success_sections)
                    )
                if failed_sections:
                    has_failure_history = True
                    parts.append(
                        "### 历史失败记录与卡点\n\n"
                        + "\n\n".join(failed_sections)
                    )
                if other_sections:
                    parts.append(
                        "### 历史辅助记录\n\n"
                        + "\n\n".join(other_sections)
                    )
        except Exception as e:
            log_system_event(f"[历史知识] execution_summary.md 读取失败: {e}", level=logging.DEBUG)

    # --- 2. 从 findings.log 提取 agent 关键发现日志 ---
    memory_file = work_dir / "findings.log"
    if memory_file.exists():
        try:
            memory_content = memory_file.read_text(encoding="utf-8").strip()
            if memory_content:
                sanitized_memory, _ = _redact_history_flags(memory_content)
                if re.search(r"^\s*-\s*status:\s*(?:success|exploited)\b", memory_content, flags=re.MULTILINE | re.IGNORECASE):
                    has_success_history = True
                parts.append(
                    "### Agent 关键发现日志 (findings.log)\n\n"
                    "每条记录包含验证标签 [VERIFIED-BY-EXECUTION] / [OBSERVED] / [UNVERIFIED-INFERENCE]。\n"
                    "- VERIFIED-BY-EXECUTION: 已实际执行命令验证，结论可信\n"
                    "- OBSERVED: 从输出中观察到，未主动测试\n"
                    "- UNVERIFIED-INFERENCE: 推断，未直接验证——**这些结论可能有误，需重新评估**\n"
                    "- paths_not_tried: 上次 agent 想到但没执行的方向，**优先尝试这些**\n"
                    "- 若其中包含成功利用记录，则攻击路径可直接复现，但新实例 FLAG 已变化，需重新读取\n\n"
                    + sanitized_memory
                )
        except Exception as e:
            log_system_event(f"[历史知识] findings.log 读取失败: {e}", level=logging.DEBUG)

    # --- 4. 从 hint.md 提取已使用的比赛提示 ---
    hint_file = work_dir / "hint.md"
    if hint_file.exists():
        try:
            hint_content = hint_file.read_text(encoding="utf-8").strip()
            if hint_content:
                sanitized_hint, _ = _redact_history_flags(hint_content)
                parts.append(
                    "### 已使用提示 (hint.md)\n\n"
                    "以下为比赛方已提供的提示记录。新会话必须考虑这些提示，"
                    "避免重复走已被 hint 否定的方向。\n\n"
                    + sanitized_hint
                )
        except Exception as e:
            log_system_event(f"[历史知识] hint.md 读取失败: {e}", level=logging.DEBUG)

    # --- 5. 从 reflection_history.md 提取反思结论 ---
    # 反思 agent 的分析结论（ABANDON 列表、被遗忘线索、推荐 Todo）是高信噪比知识，
    # 对 PromptCompiler 生成精准 focus_directives 至关重要
    reflection_file = work_dir / "dumps" / "reflection_history.md"
    if reflection_file.exists():
        try:
            reflection_content = reflection_file.read_text(encoding="utf-8").strip()
            if reflection_content:
                # 提取最后一条反思报告的关键结论部分
                last_report = _extract_last_reflection_conclusions(reflection_content)
                if last_report:
                    sanitized_report, _ = _redact_history_flags(last_report)
                    parts.append(
                        "### 反思系统结论 (reflection_history.md)\n\n"
                        "以下是反思系统对上次执行的分析结论，"
                        "包含已证明失败的方向（ABANDON）和推荐的下一步策略。\n\n"
                        + sanitized_report
                    )
        except Exception as e:
            log_system_event(f"[历史知识] reflection_history.md 读取失败: {e}", level=logging.DEBUG)

    # --- 6. 扫描工作目录中的产出文件 ---
    try:
        artifacts = []
        for f in sorted(work_dir.iterdir()):
            if f.name == "writeup.md":
                continue
            if f.is_file() and f.stat().st_size > 0:
                size_kb = f.stat().st_size // 1024
                artifacts.append(f"- `{f.name}` ({size_kb}KB)")
        if artifacts:
            parts.append(
                "### 工作目录已有文件\n"
                + "\n".join(artifacts)
                + "\n\n可通过 Read 工具查看这些文件获取更多信息。"
            )
    except Exception as e:
        log_system_event(f"[历史知识] 工作目录扫描失败: {e}", level=logging.DEBUG)

    if not parts:
        return None

    if has_success_history and has_failure_history:
        header = (
            "## 历史执行信息（含已验证路径与失败卡点）\n\n"
            "以下信息来自旧实例或旧会话。成功记录包含完整攻击路径——"
            "新实例 FLAG 已变化但路径相同，直接复现并重新读取 flag 即可；"
            "失败记录用于避坑，避免重复无效方法。\n\n"
        )
    elif has_success_history:
        header = (
            "## 历史已验证攻击路径（来自旧实例/旧会话）\n\n"
            "以下成功记录包含完整攻击路径和 flag 位置。新实例 FLAG 已变化，"
            "直接按路径复现并重新读取 flag 提交即可，禁止直接提交历史 flag 值。\n\n"
        )
    elif has_failure_history:
        header = (
            "## 历史执行信息（失败与卡点）\n\n"
            "以下是之前对本题目的失败记录和卡点，请避免重复已失败的方法，"
            "重点从上次的卡点出发尝试新思路。\n\n"
        )
    else:
        header = (
            "## 历史执行信息\n\n"
            "以下是之前对本题目的执行记录，请结合当前实例重新验证，"
            "不要直接复用历史答案。\n\n"
        )

    return header + "\n\n".join(parts)


def _append_execution_summary(
    work_dir: Path,
    attempt_number: int,
    success: bool,
    flag: Optional[str] = None,
    error: Optional[str] = None,
    elapsed: Optional[float] = None,
    cost: Optional[float] = None,
    tool_count: int = 0,
) -> None:
    """追加一条执行摘要到 {work_dir}/dumps/execution_summary.md

    每次执行结束后调用，追加结构化摘要供后续重试的 agent 读取。

    Args:
        work_dir: 题目工作目录
        attempt_number: 尝试序号
        success: 是否成功
        flag: 成功时的 flag
        error: 失败时的错误信息
        elapsed: 耗时（秒）
        cost: 花费（美元）
        tool_count: 工具调用次数
    """
    try:
        dumps_dir = work_dir / "dumps"
        dumps_dir.mkdir(parents=True, exist_ok=True)
        summary_file = dumps_dir / "execution_summary.md"

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        status = "success" if success else "failed"

        prefix = "\n" if summary_file.exists() and summary_file.stat().st_size > 0 else ""
        lines = [
            f"{prefix}## Attempt #{attempt_number} -- {now}",
            f"- Status: {status}",
        ]
        if flag:
            lines.append(f"- Flag: {flag}")
        if error:
            lines.append(f"- Error: {error}")
        if elapsed is not None:
            lines.append(f"- Duration: {elapsed:.0f}s")
        if cost is not None:
            lines.append(f"- Cost: ${cost:.2f}")
        lines.append(f"- Tools used: {tool_count}")
        lines.append("")  # trailing newline

        with open(summary_file, "a", encoding="utf-8") as f:
            f.write("\n".join(lines))

    except Exception as e:
        log_system_event(f"[ExecutionSummary] 写入失败: {e}", level=logging.WARNING)


def _resolve_tool_count(orchestrator, orchestration_result=None) -> int:
    """解析本轮执行的工具调用数。

    优先使用完整返回结果中的 tool_calls；若 query 被 timeout/cancel
    打断，则回退到 orchestrator 在流式处理中实时记录的工具数。
    """
    counts: list[int] = []
    if orchestration_result is not None:
        counts.append(len(getattr(orchestration_result, "tool_calls", []) or []))
    if orchestrator is not None:
        counts.append(int(getattr(orchestrator, "last_seen_tool_calls_count", 0) or 0))
    return max(counts, default=0)


def _build_fallback_context(
    challenge_code: str,
    category: str,
    mode: str,
    points: int,
    target_urls: list[str],
    target_ip: Optional[str],
    target_ports: list,
    work_dir: Optional[Path],
    auth_env_keys: list[str],
    user_prompt: str,
    hint: str,
    recon_data: str,
    prior_knowledge: str,
    # kb_knowledge 已移除：Agent 通过 kb_search MCP 工具按需搜索
) -> str:
    """Compiler 失败时的降级 context 拼接。

    手动将所有原始数据拼接为 context 字符串，
    保持与改造前类似的结构但消除重复。
    """
    context_parts = [
        "# CHYing Single-Challenge Execution Context",
        "## Challenge Metadata",
        f"- challenge_code: {challenge_code}",
        f"- category: {category}",
        f"- mode: {mode}",
        f"- points: {points}",
    ]
    if work_dir:
        context_parts.append(f"- work_dir: {work_dir}")
    if target_urls:
        if len(target_urls) == 1:
            context_parts.append(f"- target_url: {target_urls[0]}")
        else:
            context_parts.append("- target_urls:")
            for i, u in enumerate(target_urls, 1):
                context_parts.append(f"  - [{i}] {u}")
            context_parts.append("- Note: Multiple target URLs — probe each")
    elif target_ip and target_ports:
        context_parts.append(f"- target: {target_ip}:{','.join(map(str, target_ports))}")

    if auth_env_keys:
        context_parts.append("## Auth Environment Variables (available in container)")
        context_parts.append(
            "The following env vars are auto-injected into the exec tool environment. "
            "Use `$VAR_NAME` (Shell) or `os.environ['VAR_NAME']` (Python):"
        )
        for k in auth_env_keys:
            context_parts.append(f"- `${k}`")

    if hint:
        context_parts.append("## Competition Hints (injected)")
        context_parts.append(hint)

    if user_prompt:
        context_parts.append("## Challenge Description (user-provided)")
        context_parts.append(user_prompt)

    if recon_data:
        context_parts.append("## Automated Reconnaissance Results")
        context_parts.append(recon_data)

    # 知识库（Agent 通过 kb_search 工具按需搜索）

    if prior_knowledge:
        context_parts.append(prior_knowledge)

    context_parts.append(
        "## Objective\n"
        "- Find and submit the FLAG as quickly as possible\n"
        "- Redirect large outputs to files, return file paths\n"
    )

    return "\n\n".join(context_parts)


async def _compile_prompt(
    category: str,
    mode: str,
    challenge_code: str,
    challenge_name: str,
    points: int,
    target_urls: list[str],
    target_host_ports: str,
    work_dir: str,
    auth_env_keys: list[str],
    recon_data: str,
    prior_knowledge: str,
    user_prompt: str,
    hint: str,
    config,
) -> tuple[Optional[str], Optional[str]]:
    """编译针对本题的优化 prompt（best-effort，失败回退到 fallback context）。

    Returns:
        (compiled_prompt, corrected_category): 编译后的 prompt 和纠正后的类别（如果有）
    """
    try:
        from chying_agent.brain_agent.prompt_compiler import PromptCompiler
        from chying_agent.brain_agent.prompts import get_brain_prompt

        brain_cfg = getattr(config, "brain", None)
        compiler = PromptCompiler(
            model=getattr(brain_cfg, "model", None) or os.getenv("LLM_MODEL"),
            api_key=getattr(brain_cfg, "api_key", None) or os.getenv("LLM_API_KEY"),
            base_url=getattr(brain_cfg, "base_url", None) or os.getenv("LLM_BASE_URL"),
        )

        base_prompt = get_brain_prompt()

        compiled = await asyncio.wait_for(
            compiler.compile(
                base_prompt=base_prompt,
                category=category,
                mode=mode,
                challenge_code=challenge_code,
                challenge_name=challenge_name,
                points=points,
                target_urls=target_urls,
                target_host_ports=target_host_ports,
                work_dir=work_dir,
                auth_env_keys=auth_env_keys,
                recon_data=recon_data,
                prior_knowledge=prior_knowledge,
                user_prompt=user_prompt,
                hint=hint,
            ),
            timeout=360,
        )

        corrected_category = None
        if compiled:
            log_system_event(
                "[PromptCompiler] 编译完成",
                {"base_len": len(base_prompt), "compiled_len": len(compiled)},
            )
            # 从编译输出中提取纠正后的 category
            m = re.search(r"<resolved_category>\s*(\w+)\s*</resolved_category>", compiled)
            if not m:
                m = re.search(r"<category>(\w+)</category>", compiled)
            if not m:
                m = re.search(r"category:\s*(\w+)", compiled)
            if m:
                extracted = m.group(1).lower()
                if extracted != category.lower():
                    corrected_category = extracted
                    log_system_event(
                        f"[PromptCompiler] 类别纠正: {category} -> {corrected_category}"
                    )
        return compiled, corrected_category

    except asyncio.TimeoutError:
        log_system_event("[PromptCompiler] 编译超时，跳过专业 prompt", level=logging.WARNING)
        return None, None
    except Exception as e:
        log_system_event(f"[PromptCompiler] 编译异常: {e}，跳过专业 prompt", level=logging.WARNING)
        return None, None


# ==================== 主函数 ====================

async def solve_single_challenge(
    challenge: Dict,
    config,
    stats: Optional["ChallengeStats"],
    concurrent_semaphore: Optional[asyncio.Semaphore] = None,
    attempt_history: Optional[list] = None,
    strategy_description: str = "Orchestrator (Claude SDK)",
) -> Dict:
    """
    解决单个题目

    Args:
        challenge: 题目信息
        config: 配置
        stats: 统计管理器（可选）
        concurrent_semaphore: 并发信号量（可选，None 时不做并发控制，由调用方自行管理）
        attempt_history: 历史尝试记录（可选）
        strategy_description: 策略描述

    Returns:
        解题结果 {code, flag, score, attempts, success}

    注意: KeyboardInterrupt 会向外传播以支持优雅退出，其他异常会被捕获并返回错误结果
    """
    challenge_code = challenge.get("challenge_code", "unknown")
    points = challenge.get("points", 0)
    start_time = time.time()
    orchestrator = None

    # 并发控制：调用方可通过 concurrent_semaphore 限制并发，为 None 时跳过
    sem_ctx = concurrent_semaphore if concurrent_semaphore is not None else contextlib.nullcontext()
    log_system_event(f"[并发控制] 等待槽位: {challenge_code}")
    async with sem_ctx:
        log_system_event(f"[并发控制] 获取槽位: {challenge_code}")

        try:
            # 上下文设置必须在 try 内部，确保 finally 中 clear 配对
            set_challenge_context(challenge_code)
            try:
                set_current_challenge_code(challenge_code)
            except Exception as e:
                log_system_event(f"[上下文] set_current_challenge_code 失败: {e}", level=logging.WARNING)

            try:
                normalize_challenge_category(challenge, allow_probe=True)
            except Exception as e:
                log_system_event(f"[分类预判] 失败: {e}", level=logging.WARNING)

            try:
                _setup_work_dir(challenge, challenge_code)
            except Exception as e:
                log_system_event(f"[工作目录] 设置失败: {e}", level=logging.WARNING)

            log_system_event(f"[解题] 开始: {challenge_code}", {"points": points})
            attempt_number = len(attempt_history) + 1 if attempt_history else 1

            # --- 重做续作: 检测到历史数据则先编译精炼报告并清理 ---
            _retry_work_dir = get_current_work_dir()
            _existing_handoff = _retry_work_dir / "retry_handoff.md" if _retry_work_dir else None
            _needs_compile = (
                _retry_work_dir
                and (_retry_work_dir / "dumps" / "execution_summary.md").exists()
                and (not _existing_handoff or not _existing_handoff.exists() or _existing_handoff.stat().st_size < 100)
            )
            if _needs_compile:
                try:
                    from chying_agent.brain_agent.retry_handoff_compiler import (
                        run_retry_handoff, cleanup_work_dir_for_retry,
                    )
                    log_system_event(f"[续作] 检测到历史数据，启动 RetryHandoffCompiler")
                    from chying_agent.utils.path_utils import get_project_root
                    _log_dir = get_project_root() / "logs" / "challenges"
                    _handoff_path = await run_retry_handoff(
                        _retry_work_dir,
                        challenge_code=challenge_code,
                        log_dir=_log_dir if _log_dir.exists() else None,
                    )
                    if _handoff_path and _handoff_path.exists():
                        cleanup_work_dir_for_retry(_retry_work_dir)
                        log_system_event(
                            f"[续作] Handoff 编译成功，已清理工作目录",
                            {"handoff_size": _handoff_path.stat().st_size},
                        )
                    else:
                        log_system_event(
                            "[续作] Handoff 编译失败，降级到原 prior_knowledge 路径",
                            level=logging.WARNING,
                        )
                except Exception as e:
                    log_system_event(
                        f"[续作] RetryHandoffCompiler 异常: {e}",
                        level=logging.WARNING,
                    )

            async with ExecutionContext(challenge, attempt_number) as ctx:
                target_info = challenge.get("target_info", {})
                target_ip = target_info.get("ip")
                target_ports = target_info.get("port", [])
                category = str(challenge.get("category") or "unknown")
                mode = challenge.get("_mode") or "ctf"
                target_url = challenge.get("_target_url")
                target_urls = challenge.get("_target_urls") or []
                if not target_urls and target_url:
                    target_urls = [target_url]

                # --- 收集所有原始数据 ---

                # 侦察数据
                recon_parts: list[str] = []

                # 只要题目给了 URL 目标，就始终执行轻量 HTTP recon，
                # 不再受 category=web 的限制。很多 cloud/pentest 题目也是从 Web 入口进入。
                should_run_http_recon = bool(target_urls)
                recon_target_ip = target_ip
                recon_target_ports = target_ports
                if should_run_http_recon and target_urls and (not recon_target_ip or not recon_target_ports):
                    try:
                        parsed = urlparse(target_urls[0])
                        recon_target_ip = recon_target_ip or parsed.hostname
                        if not recon_target_ports:
                            recon_target_ports = [parsed.port or (443 if parsed.scheme == "https" else 80)]
                    except Exception:
                        pass

                if should_run_http_recon and recon_target_ip and recon_target_ports:
                    try:
                        reachable, total = _do_web_recon(
                            recon_target_ip,
                            recon_target_ports,
                            challenge_code,
                            recon_parts,
                            target_urls=target_urls,
                        )
                        # 快速失败：所有目标均不可达，直接返回 blocked 结果，不进入主循环
                        if total > 0 and reachable == 0:
                            log_system_event(
                                f"[快速失败] 所有侦察目标不可达，跳过主循环",
                                {"challenge_code": challenge_code, "total": total},
                                level=logging.WARNING,
                            )
                            return _make_result(
                                challenge_code,
                                success=False,
                                blocked_reason=(
                                    "target_unreachable: 所有目标服务均无法连接（连接拒绝/超时）。"
                                    f"已探测 {total} 个目标，全部失败。"
                                    "目标服务可能未启动、网络不通或防火墙阻断。"
                                ),
                            )
                    except Exception as e:
                        recon_parts.append(f"⚠️ 自动侦察失败: {e}")

                if category in ["pwn", "misc", "crypto"]:
                    file_info = _build_file_info(category, target_info)
                    if file_info:
                        recon_parts.append(file_info)

                recon_data = "\n\n".join(recon_parts) if recon_parts else ""

                # 历史知识
                prior_knowledge = ""
                prior_work_dir = get_current_work_dir()
                if prior_work_dir:
                    try:
                        prior = _build_prior_knowledge(
                            prior_work_dir,
                        )
                        if prior:
                            prior_knowledge = prior
                            log_system_event(f"[历史知识] 已注入上次执行信息")
                    except Exception as e:
                        log_system_event(f"[历史知识] 构建失败: {e}", level=logging.WARNING)

                # 进程内重试历史 → 拼入 prior_knowledge
                if attempt_history:
                    history_lines = []
                    for i, attempt in enumerate(attempt_history, 1):
                        if isinstance(attempt, dict):
                            history_lines.append(f"### 尝试 {i}: {attempt.get('strategy', '未知')}")
                    if history_lines:
                        attempt_history_text = (
                            "## 本次进程内重试记录\n\n"
                            + "\n".join(history_lines)
                            + "\n\n**⚠️ 请避免重复失败方法**"
                        )
                        if prior_knowledge:
                            prior_knowledge = prior_knowledge + "\n\n" + attempt_history_text
                        else:
                            prior_knowledge = attempt_history_text

                # 认证环境变量
                from chying_agent.runtime.singleton import get_config_manager
                auth_env_keys = list(get_config_manager().config.docker.passthrough_env.keys())

                # 目标 host:port 字符串
                target_host_ports = ""
                if target_ip and target_ports:
                    target_host_ports = f"{target_ip}:{','.join(map(str, target_ports))}"

                work_dir = get_current_work_dir()
                user_prompt = challenge.get("_prompt", "")

                # --- Prompt 编译 ---
                # 重做续作场景：retry_handoff.md 已是精炼报告，跳过 PromptCompiler 直接用 fallback
                # 首次执行：依赖 Compiler 识别真实靶标 URL、修正分类
                compiled_sections = None
                corrected_category = None

                _has_retry_handoff = (
                    work_dir
                    and (work_dir / "retry_handoff.md").exists()
                )

                if _has_retry_handoff:
                    log_system_event(
                        "[Prompt] 跳过 PromptCompiler（续作模式，retry_handoff.md 已就绪）"
                    )
                else:
                    compiled_output, corrected_category = await _compile_prompt(
                        category=category,
                        mode=mode,
                        challenge_code=challenge_code,
                        challenge_name=challenge.get("_challenge_name", ""),
                        points=points,
                        target_urls=target_urls,
                        target_host_ports=target_host_ports,
                        work_dir=str(work_dir) if work_dir else "",
                        auth_env_keys=auth_env_keys,
                        recon_data=recon_data,
                        prior_knowledge=prior_knowledge,
                        user_prompt=user_prompt,
                        hint=challenge.get("_hint", ""),
                        config=config,
                    )
                    compiled_sections, extracted_category = _extract_compiler_sections(compiled_output)
                    if extracted_category and not corrected_category:
                        corrected_category = extracted_category
                    if corrected_category:
                        previous_work_dir = work_dir
                        challenge["category"] = corrected_category
                        category = corrected_category

                        # 对于按 category 推导目录的题目，在编译后以最终类别重新绑定工作目录。
                        if not target_info.get("path"):
                            try:
                                _setup_work_dir(challenge, challenge_code)
                                work_dir = get_current_work_dir()
                                if previous_work_dir != work_dir:
                                    log_system_event(
                                        "[工作目录] 按编译后类别重新绑定",
                                        {
                                            "challenge_code": challenge_code,
                                            "category": category,
                                            "from": str(previous_work_dir) if previous_work_dir else "",
                                            "to": str(work_dir) if work_dir else "",
                                        },
                                    )
                            except Exception as e:
                                if previous_work_dir:
                                    set_current_work_dir(previous_work_dir)
                                    work_dir = previous_work_dir
                                log_system_event(
                                    f"[工作目录] 编译后重绑失败: {e}",
                                    level=logging.WARNING,
                                )

                        if work_dir and work_dir != previous_work_dir:
                            try:
                                refreshed_prior = _build_prior_knowledge(work_dir)
                                if refreshed_prior:
                                    prior_knowledge = refreshed_prior
                            except Exception as e:
                                log_system_event(
                                    f"[历史知识] 编译后重载失败: {e}",
                                    level=logging.DEBUG,
                                )

                # --- 构建 context：compiled prompt 替代，不再叠加 ---
                if compiled_sections:
                    context = _build_compiled_context(
                        challenge_code=challenge_code,
                        category=category,
                        mode=mode,
                        points=points,
                        target_urls=target_urls,
                        target_host_ports=target_host_ports,
                        work_dir=work_dir,
                        auth_env_keys=auth_env_keys,
                        user_prompt=user_prompt,
                        hint=challenge.get("_hint", ""),
                        compiled_sections=compiled_sections,
                    )
                else:
                    # 知识库由 Agent 通过 kb_search 工具按需搜索，不再自动注入

                    context = _build_fallback_context(
                        challenge_code=challenge_code,
                        category=category,
                        mode=mode,
                        points=points,
                        target_urls=target_urls,
                        target_ip=target_ip,
                        target_ports=target_ports,
                        work_dir=work_dir,
                        auth_env_keys=auth_env_keys,
                        user_prompt=user_prompt,
                        hint=challenge.get("_hint", ""),
                        recon_data=recon_data,
                        prior_knowledge=prior_knowledge,
                    )

                # 注入场景创建指令（需要场景但 scraper 阶段未启动的题目）
                if challenge.get("_needs_scene"):
                    platform_url = challenge.get("_platform_url", "")
                    challenge_name = challenge.get("_challenge_name", challenge_code)
                    scene_instruction = _build_scene_creation_instruction(
                        platform_url=platform_url,
                        challenge_name=challenge_name,
                        challenge_id=challenge.get("_challenge_id", ""),
                    )
                    context = scene_instruction + "\n\n" + context

                # 在最终 category/work_dir 固化后创建 Orchestrator，
                # 避免外层提前实例化导致 cwd 固定在错误目录。
                # system prompt = 自定义领域 prompt，tools = Claude Code preset
                from chying_agent.brain_agent.claude_advisor import ClaudeOrchestrator

                def _create_orchestrator():
                    brain_cfg = getattr(config, "brain", None)
                    _orch_work_dir = get_current_work_dir()
                    return ClaudeOrchestrator(
                        model=getattr(brain_cfg, "model", None) or os.getenv("LLM_MODEL"),
                        api_key=getattr(brain_cfg, "api_key", None) or os.getenv("LLM_API_KEY"),
                        base_url=getattr(brain_cfg, "base_url", None) or os.getenv("LLM_BASE_URL"),
                        cli_path=getattr(brain_cfg, "cli_path", None),
                        category=category,
                        mode=mode,
                        work_dir=str(_orch_work_dir) if _orch_work_dir else None,
                    )

                orchestrator = _create_orchestrator()

                # 执行 Orchestrator（带会话轮转 + 分支探索）
                #
                # 两层恢复机制：
                # 1. 同 session 内 compact 恢复（base.py Guidance Loop 内）：
                #    CLI auto-compact 触发时，异步启动 ProgressCompiler 产出 compact_handoff.md，
                #    hook 引导 Agent 读 handoff 快速恢复。Agent 继续在同一 CLI session 中运行。
                #    触发条件：上下文用量超阈值 → status:"compacting"
                #    ⚡ 这是主要恢复路径，实际比赛中 compact 频繁触发。
                #
                # 2. 跨 session 的 Session Rotation（本层循环）：
                #    Guidance Loop 判定 Agent 摘要重复 3+ 轮（session_exhausted=True）→
                #    销毁整个 CLI session → 创建全新 orchestrator + 重建初始 context。
                #    此时调用 _build_fresh_session_context_with_compiler() 同步启动
                #    ProgressCompiler 为新 session 编写完整的接手文档。
                #    触发条件：_build_guidance_query 返回 is_exhausted=True
                #    ⚠️ 注意：当前实现中此路径极少触发（session 通常先 timeout），
                #    作为安全网保留——如果 Agent 在同 session 内彻底卡死，
                #    Session Rotation 提供"换人接手"的机会。
                MAX_SESSION_ROTATIONS = 2
                orchestration_result = None
                attempt_tool_count_total = 0
                session_inflight = False
                current_context = context
                try:
                    async with asyncio.timeout(DEFAULT_SINGLE_TASK_TIMEOUT):
                        for session_idx in range(MAX_SESSION_ROTATIONS):
                            session_inflight = True
                            orchestration_result = await orchestrator.run(context=current_context)
                            session_inflight = False
                            attempt_tool_count_total += _resolve_tool_count(orchestrator, orchestration_result)
                            # 检测 recon_complete: 侦察完成且有多个攻击面，启动分支探索
                            structured = orchestration_result.structured_data if orchestration_result else None
                            if (
                                structured
                                and isinstance(structured, dict)
                                and structured.get("recon_complete")
                                and structured.get("attack_vectors")
                                and len(structured["attack_vectors"]) > 1
                                and not _is_solved_check(orchestration_result)
                            ):
                                branch_result = await _run_branch_exploration(
                                    vectors=structured["attack_vectors"],
                                    base_context=context,
                                    create_orchestrator=_create_orchestrator,
                                    work_dir=get_current_work_dir(),
                                )
                                if branch_result is not None:
                                    attempt_tool_count_total += len(branch_result.tool_calls or [])
                                    orchestration_result = branch_result
                                break

                            if not getattr(orchestration_result, 'session_exhausted', False):
                                break

                            log_system_event(
                                f"[Session Rotation] 会话耗尽，开新会话 ({session_idx + 2}/{MAX_SESSION_ROTATIONS})",
                            )
                            await orchestrator.reset_persistent_session()
                            current_context = await _build_fresh_session_context_with_compiler(
                                base_context=context,
                                work_dir=get_current_work_dir(),
                                config=config,
                            )
                            orchestrator = _create_orchestrator()

                except asyncio.TimeoutError:
                    log_system_event(f"[解题] 超时: {challenge_code}", level=logging.WARNING)
                    ctx.set_result(orchestration_result, success=False, error="timeout")
                    if stats:
                        await stats.record_failure(challenge_code)
                    _wd = get_current_work_dir()
                    if _wd:
                        inflight_tool_count = (
                            int(getattr(orchestrator, "last_seen_tool_calls_count", 0) or 0)
                            if session_inflight else 0
                        )
                        _append_execution_summary(
                            _wd,
                            attempt_number,
                            success=False,
                            error="timeout",
                            elapsed=time.time() - start_time,
                            tool_count=attempt_tool_count_total + inflight_tool_count,
                        )
                    return _make_result(challenge_code, timeout=True)

                except asyncio.CancelledError:
                    log_system_event(f"[解题] 取消: {challenge_code}", level=logging.WARNING)
                    ctx.set_result(orchestration_result, success=False, error="cancelled")
                    if stats:
                        await stats.record_failure(challenge_code)
                    _wd = get_current_work_dir()
                    if _wd:
                        inflight_tool_count = (
                            int(getattr(orchestrator, "last_seen_tool_calls_count", 0) or 0)
                            if session_inflight else 0
                        )
                        _append_execution_summary(
                            _wd,
                            attempt_number,
                            success=False,
                            error="cancelled",
                            elapsed=time.time() - start_time,
                            tool_count=attempt_tool_count_total + inflight_tool_count,
                        )
                    return _make_result(challenge_code, cancelled=True)

                except KeyboardInterrupt:
                    # 用户中断，向外传播以支持优雅退出
                    ctx.set_result(orchestration_result, success=False, error="user_interrupt")
                    _wd = get_current_work_dir()
                    if _wd:
                        inflight_tool_count = (
                            int(getattr(orchestrator, "last_seen_tool_calls_count", 0) or 0)
                            if session_inflight else 0
                        )
                        _append_execution_summary(
                            _wd,
                            attempt_number,
                            success=False,
                            error="user_interrupt",
                            elapsed=time.time() - start_time,
                            tool_count=attempt_tool_count_total + inflight_tool_count,
                        )
                    raise

                except Exception as e:
                    log_system_event(f"[解题] 异常: {challenge_code} - {e}", level=logging.ERROR)
                    ctx.set_result(orchestration_result, success=False, error=str(e))
                    if stats:
                        await stats.record_failure(challenge_code)
                    _wd = get_current_work_dir()
                    if _wd:
                        inflight_tool_count = (
                            int(getattr(orchestrator, "last_seen_tool_calls_count", 0) or 0)
                            if session_inflight else 0
                        )
                        _append_execution_summary(
                            _wd,
                            attempt_number,
                            success=False,
                            error=str(e),
                            elapsed=time.time() - start_time,
                            tool_count=attempt_tool_count_total + inflight_tool_count,
                        )
                    return _make_result(challenge_code, error=str(e))

            # 处理结果
            elapsed_time = time.time() - start_time

            if orchestration_result is None:
                ctx.set_result(None, success=False, error="no_result")
                if stats:
                    await stats.record_failure(challenge_code)
                _wd = get_current_work_dir()
                if _wd:
                    _append_execution_summary(
                        _wd,
                        attempt_number,
                        success=False,
                        error="no_result",
                        elapsed=elapsed_time,
                        tool_count=attempt_tool_count_total,
                    )
                return _make_result(challenge_code, error="no_result", elapsed_time=elapsed_time)

            if orchestration_result.is_error:
                error_msg = orchestration_result.error_message or "orchestrator_error"
                ctx.set_result(orchestration_result, success=False, error=error_msg)
                if stats:
                    await stats.record_failure(challenge_code)
                _wd = get_current_work_dir()
                if _wd:
                    tool_count = attempt_tool_count_total
                    _append_execution_summary(_wd, attempt_number, success=False, error=error_msg, elapsed=elapsed_time, tool_count=tool_count)
                return _make_result(challenge_code, error=error_msg, elapsed_time=elapsed_time)

            # 提取 flag
            structured = orchestration_result.structured_data
            if not isinstance(structured, dict):
                structured = getattr(orchestrator, "last_structured_response", None) or {}

            # 优先信任结构化输出的 solved 字段。
            # 当 agent 明确报告 solved=false 时，不从文本中提取 flag——
            # 因为 agent 的分析文本可能提及之前尝试过的错误 flag（如 "Wrong flag: CTF{...}"），
            # 正则会误匹配，导致把失败结果误判为成功。
            structured_solved = structured.get("solved") if structured.get("solved") is not None else structured.get("success")
            solved = _is_truthy(structured_solved) if structured_solved is not None else None

            raw_flag = structured.get("flag") or structured.get("FLAG")
            _INVALID_FLAG_VALUES = ("null", "none", "n/a", "no", "false", "")
            if raw_flag and raw_flag.strip().lower() not in _INVALID_FLAG_VALUES:
                flag = raw_flag.strip()
            elif solved is not False:
                # 仅当 solved 不是明确的 false 时，才回退从文本提取 flag
                flag = _extract_flag(orchestration_result.text)
            else:
                flag = None

            # 最终 solved 判定：结构化字段优先，无结构化字段时根据是否有 flag 兜底
            if solved is None:
                solved = bool(flag)
            elif flag and not solved:
                # 结构化声明失败但提取到了 flag——以结构化为准，丢弃可能误提取的 flag
                flag = None
                solved = False
            attempts = attempt_tool_count_total

            extras = {"elapsed_time": elapsed_time}
            if structured.get("summary"):
                extras["summary"] = structured["summary"]

            if solved and flag:
                log_system_event(f"[解题] 成功: {challenge_code}", {"flag": flag})
                ctx.set_result(orchestration_result, success=True, flag=flag, score=points)
                if stats:
                    await stats.record_success(challenge_code)

                # 自动生成 writeup（通过 ENABLE_WRITEUP=0 或 false 关闭，比赛场景省时）
                _writeup_wd = get_current_work_dir()
                _writeup_enabled = os.getenv("ENABLE_WRITEUP", "1").strip().lower() not in ("0", "false", "no")
                if _writeup_wd and _writeup_enabled:
                    try:
                        from chying_agent.writeup_generator import generate_writeup
                        log_system_event(f"[Writeup] 开始自动生成: {challenge_code}")
                        writeup_info = {
                            "challenge_code": challenge_code,
                            "mode": mode,
                            "category": category,
                            "points": points,
                            "flag": flag,
                        }
                        if target_urls:
                            writeup_info["target_url"] = target_urls[0]
                        if target_ip:
                            writeup_info["target_ip"] = target_ip
                        await generate_writeup(_writeup_wd, writeup_info, challenge_db_id=ctx.challenge_db_id)
                    except Exception as e:
                        log_system_event(f"[Writeup] 自动生成失败: {e}", level=logging.WARNING)

                # 自动提交 flag 到平台
                _platform_url = challenge.get("_platform_url")
                _challenge_id = challenge.get("_challenge_id")
                _challenge_name = challenge.get("_challenge_name", challenge_code)
                if _platform_url and _challenge_id:
                    try:
                        from chying_agent.contest.platform_runner import submit_flag
                        log_system_event(f"[FlagSubmit] 开始自动提交: {challenge_code}")
                        submit_ok, submit_msg = await submit_flag(
                            _platform_url, _challenge_name, _challenge_id, flag
                        )
                        if submit_ok:
                            log_system_event(
                                f"[FlagSubmit] 提交成功: {challenge_code}",
                                {"message": submit_msg},
                            )
                        else:
                            log_system_event(
                                f"[FlagSubmit] 提交失败: {challenge_code}",
                                {"message": submit_msg},
                                level=logging.WARNING,
                            )
                    except Exception as e:
                        log_system_event(
                            f"[FlagSubmit] 提交异常: {e}",
                            level=logging.WARNING,
                        )

                _wd = get_current_work_dir()
                if _wd:
                    _append_execution_summary(
                        _wd, attempt_number, success=True, flag=flag,
                        elapsed=elapsed_time, cost=getattr(orchestration_result, 'cost', None),
                        tool_count=attempts,
                    )

                return _make_result(challenge_code, flag=flag, score=points, attempts=attempts, success=True, **extras)

            log_system_event(f"[解题] 失败: {challenge_code}")
            ctx.set_result(orchestration_result, success=False, error="no_flag_found")
            if stats:
                await stats.record_failure(challenge_code)
            _wd = get_current_work_dir()
            if _wd:
                _append_execution_summary(
                    _wd, attempt_number, success=False, error="no_flag_found",
                    elapsed=elapsed_time, cost=getattr(orchestration_result, 'cost', None),
                    tool_count=attempts,
                )
            return _make_result(challenge_code, attempts=attempts, **extras)

        except KeyboardInterrupt:
            # 向外传播用户中断
            raise

        except asyncio.CancelledError:
            log_system_event(f"[解题] 任务被取消: {challenge_code}", level=logging.WARNING)
            raise

        except Exception as e:
            log_system_event(f"[解题] 严重异常: {challenge_code} - {e}", level=logging.CRITICAL)
            if stats:
                await stats.record_failure(challenge_code)
            return _make_result(challenge_code, error=f"critical: {e}", elapsed_time=time.time() - start_time)

        finally:
            if orchestrator is not None and orchestrator.is_session_active:
                try:
                    await orchestrator.reset_persistent_session()
                except Exception as e:
                    log_system_event(
                        f"[Orchestrator] 会话清理失败: {e}",
                        level=logging.DEBUG,
                    )
            # 清理 WSS 终端会话
            try:
                await cleanup_session_manager(challenge_code)
            except Exception:
                pass
            # 清理上下文
            clear_challenge_context()
            clear_current_challenge_code()
