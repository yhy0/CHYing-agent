"""Hook 工厂函数与辅助工具

从 base.py 提取的 Hook 相关功能：
- create_pre_tool_use_hook: PreToolUse Hook 工厂（含 ABANDON 强制执行）
- create_post_tool_use_hook: PostToolUse Hook 工厂
- create_subagent_stop_hook: SubagentStop Hook 工厂
- _matches_dead_end: Dead End 匹配（供 ABANDON 使用）
- 辅助函数: _sync_todos_to_progress, _read_subagent_findings
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import (
    Optional,
    Dict,
    Any,
    List,
    cast,
)

from claude_agent_sdk import (
    HookContext,
    HookCallback,
    HookJSONOutput,
    PreToolUseHookInput,
    PostToolUseHookInput,
    SubagentStopHookInput,
)

from ..common import log_tool_event, log_todo_event, log_system_event, format_tool_source_prefix
from .file_guards import check_file_read
from .reflection import (
    ReflectionAction,
    ReflectionTracker,
    build_soft_warning_text,
)

# 模块级 logger
_logger = logging.getLogger(__name__)


def _sync_todos_to_progress(todos: list[dict]) -> None:
    """将 TodoWrite 的 todos 同步写入 progress.md 的「当前阶段」和「攻击计划」段落。

    progress.md 是 compact 恢复的锚点，但 LLM 几乎不主动更新它。
    TodoWrite 是 agent 已经在调用的工具，这里利用它自动同步进度。
    """
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if not work_dir:
            return

        progress_file = work_dir / "progress.md"
        if not progress_file.exists():
            return

        content = progress_file.read_text(encoding="utf-8")

        # 计算进度统计
        total = len(todos)
        done = sum(1 for t in todos if t.get("status") == "completed")
        current_items = [
            t for t in todos if t.get("status") == "in_progress"
        ]
        current_desc = current_items[0].get("content", "未知") if current_items else "无"

        # 构建替换段落
        lines = []
        for t in todos:
            status = t.get("status", "pending")
            text = t.get("content", "")
            if status == "completed":
                lines.append(f"- [x] {text}")
            elif status == "in_progress":
                lines.append(f"- [ ] **{text}** ← 当前")
            else:
                lines.append(f"- [ ] {text}")

        new_section = (
            f"In progress — {current_desc} ({done}/{total} done)\n\n"
            f"### Attack Plan (auto-synced from TodoWrite)\n\n"
            + "\n".join(lines)
        )

        # 替换 "Current Phase" 段落（从 ## Current Phase 到下一个 ## 标题之前）
        import re

        pattern = re.compile(
            r"(## Current Phase\n\n).*?(?=\n## |\Z)",
            re.DOTALL,
        )
        if pattern.search(content):
            content = pattern.sub(r"\g<1>" + new_section, content)
        else:
            # 没有找到段落，追加到末尾
            content = content.rstrip() + f"\n\n## Current Phase\n\n{new_section}\n"

        progress_file.write_text(content, encoding="utf-8")
    except Exception:
        pass


def load_skill_hints(skills_dir: str) -> Optional[str]:
    """从 .claude/skills/ 目录读取所有 skill 的 name+description，拼接为提示文本。

    Returns:
        skill 提示文本（含名称和描述），无 skill 时返回 None
    """
    from pathlib import Path

    skills_path = Path(skills_dir)
    if not skills_path.is_dir():
        return None

    lines: list[str] = []
    for skill_dir in sorted(skills_path.iterdir()):
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            continue
        name = ""
        description = ""
        try:
            for raw_line in skill_md.read_text(encoding="utf-8").splitlines()[:10]:
                stripped = raw_line.strip()
                if stripped.startswith("name:"):
                    name = stripped[5:].strip()
                elif stripped.startswith("description:"):
                    description = stripped[12:].strip()
                if name and description:
                    break
        except Exception:
            continue
        if name and description:
            lines.append(f"- **{name}**: {description}")

    if not lines:
        return None

    return (
        "\n\nAVAILABLE SKILLS (call Skill tool to load domain knowledge on demand):\n"
        + "\n".join(lines)
        + "\n\nIf a skill matches your current challenge type, call Skill(\"<skill-name>\") "
        "to load its methodology BEFORE attempting exploitation."
    )


def _read_subagent_findings() -> Optional[str]:
    """读取子代理通过 record_key_finding 写入的关键发现。

    Task/Agent 工具完成后，从 findings.log 读取最新发现，
    作为 PostToolUse additionalContext 注入 Orchestrator 上下文。
    """
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if not work_dir:
            return None
        memory_md = work_dir / "findings.log"
        if not memory_md.exists():
            return None
        content = memory_md.read_text(encoding="utf-8").strip()
        if not content:
            return None
        return (
            "## Sub-agent Key Findings (from record_key_finding)\n\n"
            "IMPORTANT: Review these findings carefully. They contain discoveries "
            "made by the sub-agent that just completed. Use them to plan your next steps.\n\n"
            + content
        )
    except Exception:
        return None


def _get_compact_recovery_files() -> frozenset[str]:
    """返回 compact 恢复时必须读取的文件集合。

    基础恢复锚点固定为 progress / findings。
    当题目目录下已存在 hint.md 且非空时，将其纳入恢复集合，
    避免 compact 后遗忘比赛方提供的 hint。
    """
    required = {"progress.md", "findings.log"}
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if work_dir:
            hint_file = work_dir / "hint.md"
            if hint_file.exists() and hint_file.read_text(encoding="utf-8").strip():
                required.add("hint.md")
    except Exception:
        pass
    return frozenset(required)


def _try_get_handoff_path(reflection_tracker) -> Optional[str]:
    """非阻塞检查 ProgressCompiler 异步任务是否已完成且产出了 handoff 文件。

    compact 开始时异步启动的 ProgressCompiler 与 CLI 摘要并行运行。
    此函数在 PreToolUse hook 中调用——如果 handoff 已就绪，
    推荐 Agent 读取它（一步恢复）而非逐个读 progress.md + findings.log。

    Returns:
        handoff 文件的绝对路径字符串（已就绪且 >100 字节），否则 None。
    """
    task = getattr(reflection_tracker, "_progress_compiler_task", None)
    if task is None or not task.done():
        return None
    try:
        handoff_path = task.result()
        if handoff_path and handoff_path.exists() and handoff_path.stat().st_size > 100:
            return str(handoff_path)
    except Exception:
        pass
    return None


def _write_checkpoint(entries: list[str], cp_number: int) -> None:
    """Auto checkpoint: 追加 dumps/checkpoints.log + 覆盖 progress.md 的 Auto Checkpoint section。"""
    import re

    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if not work_dir:
            return

        now = datetime.now().strftime("%H:%M")
        start = (cp_number - 1) * 15 + 1
        end = cp_number * 15
        header = f"### CP@{now} (tools {start}-{end})"
        safe_entries = [
            _sanitize_text_for_markdown(entry).strip()
            for entry in entries
            if _sanitize_text_for_markdown(entry).strip()
        ]
        body = "\n".join(safe_entries)
        block = f"{header}\n{body}\n\n"

        # 追加到 dumps/checkpoints.log
        dumps_dir = work_dir / "dumps"
        dumps_dir.mkdir(parents=True, exist_ok=True)
        cp_log = dumps_dir / "checkpoints.log"
        with open(cp_log, "a", encoding="utf-8") as f:
            f.write(block)

        # 覆盖 progress.md 的 ## Auto Checkpoint section（只留最新）
        progress_file = work_dir / "progress.md"
        if progress_file.exists():
            content = progress_file.read_text(encoding="utf-8")
            new_section = f"## Auto Checkpoint\n> CP@{now} (tools {start}-{end}) — 最新\n{body}\n"
            pattern = re.compile(r"## Auto Checkpoint\n.*?(?=\n## |\Z)", re.DOTALL)
            if pattern.search(content):
                content = pattern.sub(new_section, content)
            else:
                content = content.rstrip() + f"\n\n{new_section}\n"
            progress_file.write_text(content, encoding="utf-8")

        _logger.info(f"Auto checkpoint #{cp_number} written ({len(entries)} entries)")
    except Exception as e:
        _logger.warning(f"Auto checkpoint write failed: {e}")


def _extract_subagent_yaml(result_text: str) -> Optional[dict]:
    """从子代理返回文本中提取最后一个 ```yaml ... ``` block 并解析。

    Returns: parsed dict, or None if no valid YAML block found.
    """
    import re
    import yaml

    # 匹配最后一个 ```yaml ... ``` block
    pattern = re.compile(r"```yaml\s*\n(.*?)```", re.DOTALL)
    matches = pattern.findall(result_text)
    if not matches:
        return None
    try:
        data = yaml.safe_load(matches[-1])  # 取最后一个
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return None


def _extract_keywords(text: str) -> set[str]:
    """从文本中提取关键词，用于 dead end 匹配。

    提取规则：
    - URL 路径（/path/to/endpoint）
    - 域名/主机名（xxx.example.com）
    - 端口号（:8080）
    - CVE 编号（CVE-2024-1234）
    - 技术/服务名词（3+ 字符的字母数字 token）
    - 错误消息模式（引号内的内容）

    Returns:
        小写关键词集合
    """
    import re

    keywords: set[str] = set()
    lower = text.lower()

    # URL 路径 (/prod/register, /api/v1/users)
    for m in re.finditer(r"(/[\w./-]{3,})", lower):
        keywords.add(m.group(1))

    # 域名/主机名 (xxx.example.com, localhost)
    for m in re.finditer(r"\b([\w.-]+\.(?:com|org|net|io|local|internal|cloud|aws|azure))\b", lower):
        keywords.add(m.group(1))

    # 端口号 (:8080, :443)
    for m in re.finditer(r":(\d{2,5})\b", lower):
        keywords.add(f":{m.group(1)}")

    # CVE 编号
    for m in re.finditer(r"(cve-\d{4}-\d+)", lower):
        keywords.add(m.group(1))

    # 引号内的错误消息/关键短语
    for m in re.finditer(r"['\"]([^'\"]{4,60})['\"]", lower):
        keywords.add(m.group(1).strip())

    # 技术/服务名词 token（3+ 字符，字母数字+连字符）
    # 排除常见停用词
    _STOPWORDS = frozenset({
        "the", "and", "for", "with", "from", "that", "this", "not", "all",
        "any", "has", "was", "are", "but", "been", "have", "will", "can",
        "each", "which", "their", "there", "been", "some", "returns",
        "using", "when", "command", "function", "true", "false", "none",
        "null", "error", "failed", "success", "request", "response",
    })
    for m in re.finditer(r"\b([a-z][a-z0-9_-]{2,})\b", lower):
        token = m.group(1)
        if token not in _STOPWORDS:
            keywords.add(token)

    return keywords


def _matches_dead_end(
    tool_name: str,
    tool_input: Optional[Dict[str, Any]],
    reflection_tracker: Optional["ReflectionTracker"] = None,
) -> Optional[str]:
    """检查工具调用是否匹配已确认的 Dead End 方向。

    三层匹配策略（从宽到严）：

    层 1: 关键词匹配（最重要）
        从 dead end 文本和工具 input 中提取关键词（URL、域名、端口、服务名等），
        2+ 个关键词交集命中即 block。

    层 2: 调用签名匹配
        ABANDON 激活后，从 ReflectionTracker 的 _call_history 中提取
        激活前最后 N 次调用的签名模式。新调用的签名匹配这些模式则 block。

    层 3: CVE 匹配（保留原有逻辑）
        提取 CVE 编号交集匹配。

    设计原则：宁可多拦——被拦后模型会收到 deny reason 提示换方向，
    误拦代价（少一次无效调用）远小于漏拦代价（30 轮重复尝试）。

    Args:
        tool_name: 工具名称
        tool_input: 工具输入参数
        reflection_tracker: 反思追踪器（可选），用于签名匹配

    Returns:
        匹配到的 dead end 描述（用于日志和 block reason），未匹配返回 None
    """
    import re

    if not tool_input:
        return None

    try:
        from ..runtime.context import get_current_work_dir
        from .reflection import extract_dead_ends, ReflectionTracker as _RT

        work_dir = get_current_work_dir()
        if not work_dir:
            return None

        dead_ends = extract_dead_ends(work_dir)

        input_str = json.dumps(tool_input, ensure_ascii=False).lower()
        input_keywords = _extract_keywords(input_str)

        # === 层 1: 关键词匹配 ===
        if dead_ends and input_keywords:
            for dead_end in dead_ends:
                dead_keywords = _extract_keywords(dead_end.lower())
                overlap = input_keywords & dead_keywords
                if len(overlap) >= 2:
                    return f"{dead_end} [keyword match: {', '.join(sorted(list(overlap)[:5]))}]"

        # === 层 2: 调用签名匹配 ===
        if reflection_tracker is not None:
            stagnation_sigs = reflection_tracker.get_stagnation_signatures()
            if stagnation_sigs:
                current_sig = _RT._make_call_signature(tool_name, tool_input)
                for old_sig in stagnation_sigs:
                    if current_sig == old_sig:
                        return f"Repeated stagnation pattern [signature: {current_sig}]"

        # === 层 3: CVE 匹配 ===
        if dead_ends:
            cves_in_input = set(re.findall(r"cve-\d{4}-\d+", input_str))
            if cves_in_input:
                for dead_end in dead_ends:
                    dead_lower = dead_end.lower()
                    cves_in_dead = set(re.findall(r"cve-\d{4}-\d+", dead_lower))
                    if cves_in_dead and cves_in_input & cves_in_dead:
                        return dead_end

    except Exception:
        pass

    return None


def _get_timeline_path() -> Optional[Path]:
    """返回当前工作目录下的 attack_timeline.md 路径"""
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if work_dir:
            return work_dir / "attack_timeline.md"
    except Exception:
        pass
    return None


def _get_current_work_dir_str() -> Optional[str]:
    """返回当前题目工作目录的字符串路径"""
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if work_dir:
            return str(work_dir)
    except Exception:
        pass
    return None


def _sanitize_text_for_markdown(text: str) -> str:
    """清理将写入 markdown/log 文件的文本，去除 NUL 和大部分控制字符。"""
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    return "".join(
        ch for ch in text
        if ch in ("\n", "\t") or ord(ch) >= 32
    )


def _append_timeline(timeline_path: Path, entry: str) -> None:
    """追加一行到 attack_timeline.md"""
    try:
        safe_entry = _sanitize_text_for_markdown(entry).strip()
        if not safe_entry:
            return
        with open(timeline_path, "a", encoding="utf-8") as f:
            f.write(safe_entry + "\n")
    except Exception:
        pass


def _replace_or_append_section(content: str, section_title: str, body: str) -> str:
    """替换或追加 progress.md 中的指定 section。"""
    import re

    safe_body = _sanitize_text_for_markdown(body).strip()
    pattern = re.compile(
        rf"(## {re.escape(section_title)}\n\n).*?(?=\n## |\Z)",
        re.DOTALL,
    )
    if pattern.search(content):
        return pattern.sub(r"\g<1>" + safe_body + "\n", content)
    return content.rstrip() + f"\n\n## {section_title}\n\n{safe_body}\n"


def _merge_progress_bullets(
    content: str,
    section_title: str,
    items: list[str],
    *,
    max_items: int = 8,
) -> str:
    """将条目合并进 progress.md 的某个 bullet section。

    - 去重（保持顺序）
    - 仅保留最近 max_items 条
    """
    cleaned_items = [
        _sanitize_text_for_markdown(str(item)).strip()
        for item in items
        if _sanitize_text_for_markdown(str(item)).strip()
    ]
    if not cleaned_items:
        return content

    existing_items: list[str] = []
    import re

    match = re.search(
        rf"## {re.escape(section_title)}\n\n(.*?)(?=\n## |\Z)",
        content,
        re.DOTALL,
    )
    if match:
        for line in match.group(1).splitlines():
            stripped = line.strip()
            if stripped.startswith("- "):
                existing_items.append(stripped[2:].strip())

    merged: list[str] = []
    seen: set[str] = set()
    for item in existing_items + cleaned_items:
        if item and item not in seen:
            seen.add(item)
            merged.append(item)

    if max_items > 0 and len(merged) > max_items:
        merged = merged[-max_items:]

    body = "\n".join(f"- {item}" for item in merged)
    return _replace_or_append_section(content, section_title, body)


def _sync_hint_summary_to_progress(hint_text: str) -> None:
    """将 hint 的摘要同步到 progress.md 的 Hints Used 段落。"""
    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if not work_dir:
            return
        progress_file = work_dir / "progress.md"
        if not progress_file.exists():
            return

        summary = " ".join(str(hint_text or "").strip().split())
        if not summary:
            return
        summary = summary[:220]
        now = datetime.now().strftime("%H:%M")
        item = f"[{now}] {summary}"

        content = progress_file.read_text(encoding="utf-8")
        updated = _merge_progress_bullets(
            content,
            "Hints Used",
            [item],
            max_items=5,
        )
        progress_file.write_text(updated, encoding="utf-8")
    except Exception:
        pass


def _sync_subagent_result_to_progress(
    tool_name: str,
    tool_input: dict,
    yaml_data: Optional[dict],
    result_text: str,
) -> None:
    """在 Task/Agent 完成时，将最新子代理状态刷入 progress.md。"""
    import re

    try:
        from ..runtime.context import get_current_work_dir

        work_dir = get_current_work_dir()
        if not work_dir:
            return
        progress_file = work_dir / "progress.md"
        if not progress_file.exists():
            return

        content = progress_file.read_text(encoding="utf-8")
        now = datetime.now().strftime("%H:%M")
        subagent_label = ""
        if isinstance(tool_input, dict):
            subagent_label = str(
                tool_input.get("subagent_type")
                or tool_input.get("description")
                or tool_name
            ).strip()
        if not subagent_label:
            subagent_label = tool_name

        phase_lines = [f"Subagent update @ {now} — {subagent_label}"]
        next_steps: list[str] = []
        artifact_items_for_progress: list[str] = []
        checkpoint_lines: list[str] = [f"- subagent: {subagent_label}"]

        if isinstance(yaml_data, dict):
            result_state = str(yaml_data.get("result", "partial")).strip() or "partial"
            phase_lines.append(f"Result: {result_state}")
            checkpoint_lines.append(f"- result: {result_state}")

            summary_text = str(yaml_data.get("summary", "")).strip()
            if summary_text:
                summary_preview = re.sub(r"\s+", " ", summary_text)[:240]
                phase_lines.append(f"Summary: {summary_preview}")
                checkpoint_lines.append(f"- summary: {summary_preview}")

            anomaly = str(yaml_data.get("highest_anomaly", "")).strip()
            if anomaly and anomaly != "null":
                phase_lines.append(f"Highest anomaly: {anomaly}")
                checkpoint_lines.append(f"- highest_anomaly: {anomaly}")

            new_findings = yaml_data.get("new_findings")
            finding_titles: list[str] = []
            if isinstance(new_findings, list):
                for item in new_findings[:5]:
                    if isinstance(item, dict):
                        title = str(item.get("title", "")).strip()
                        if title and title not in finding_titles:
                            finding_titles.append(title)
            if finding_titles:
                phase_lines.append("Key findings: " + "; ".join(finding_titles[:3]))
                checkpoint_lines.extend(
                    [f"- finding: {title}" for title in finding_titles[:3]]
                )

            hypotheses = yaml_data.get("next_hypotheses")
            if isinstance(hypotheses, list):
                for hypothesis in hypotheses[:5]:
                    text = str(hypothesis).strip()
                    if text and text not in next_steps:
                        next_steps.append(text)

            explicit_next_steps = yaml_data.get("next_steps")
            if isinstance(explicit_next_steps, list):
                for step in explicit_next_steps[:5]:
                    text = str(step).strip()
                    if text and text not in next_steps:
                        next_steps.append(text)

            artifact_paths = yaml_data.get("artifact_paths")
            if isinstance(artifact_paths, list):
                artifact_lines = []
                for path in artifact_paths[:5]:
                    path_text = str(path).strip()
                    if path_text:
                        artifact_lines.append(path_text)
                if artifact_lines:
                    artifact_items_for_progress.extend(artifact_lines)
                    phase_lines.append("Artifacts: " + "; ".join(artifact_lines[:3]))
                    checkpoint_lines.extend(
                        [f"- artifact: {path}" for path in artifact_lines[:3]]
                    )

            stop_reason = str(yaml_data.get("stop_reason", "")).strip()
            if stop_reason:
                phase_lines.append(f"Stop reason: {stop_reason}")
                checkpoint_lines.append(f"- stop_reason: {stop_reason}")
        else:
            preview = _sanitize_text_for_markdown(result_text).strip()
            if preview:
                preview = re.sub(r"\s+", " ", preview)[:240]
                phase_lines.append(f"Summary: {preview}")
                checkpoint_lines.append(f"- summary: {preview}")

        current_phase_match = re.search(
            r"## Current Phase\n\n(.*?)(?=\n## |\Z)",
            content,
            re.DOTALL,
        )
        current_phase_body = current_phase_match.group(1).strip() if current_phase_match else ""
        attack_plan_part = ""
        attack_plan_marker = "### Attack Plan (auto-synced from TodoWrite)"
        if attack_plan_marker in current_phase_body:
            attack_plan_part = current_phase_body[current_phase_body.index(attack_plan_marker):].strip()

        latest_update_body = "### Latest Subagent Update\n\n" + "\n".join(phase_lines)
        if attack_plan_part:
            latest_update_body += "\n\n" + attack_plan_part
        content = _replace_or_append_section(content, "Current Phase", latest_update_body)

        if next_steps:
            next_steps_body = "\n".join(f"- {step}" for step in next_steps)
            content = _replace_or_append_section(content, "Next Steps", next_steps_body)

        if artifact_items_for_progress:
            content = _merge_progress_bullets(
                content,
                "Key Artifacts",
                [f"[{now}] {path}" for path in artifact_items_for_progress[:5]],
                max_items=8,
            )

        checkpoint_body = (
            f"> Subagent@{now} ({subagent_label}) — 最新\n"
            + "\n".join(checkpoint_lines)
        )
        content = _replace_or_append_section(content, "Auto Checkpoint", checkpoint_body)

        progress_file.write_text(content, encoding="utf-8")
    except Exception:
        pass


def _format_timeline_entry(
    tool_name: str,
    tool_input: dict,
    tool_response: Any,
    is_error: bool,
    is_subagent: bool,
    subagent_name: str,
) -> list[str]:
    """从工具调用生成 timeline 条目列表（调用行 + 可选结果行），返回空列表表示跳过。

    记录策略：
    - exec / wss_exec: 命令前120字符 + STDOUT前100字符
    - wss_connect: 完整参数 + session_id + banner
    - record_key_finding: kind + title + "OK: recorded xxx"
    - Task/Agent 委派: subagent_type + description + prompt前150字符
    - kb_search: query（不记录结果）
    - 子代理 navigate/fill_form/evaluate_script: 关键参数（不记录结果）
    - 子代理 click/snapshot/hover/press_key 等 UI: 跳过
    - Read/Glob/Grep/Write/Edit/TodoWrite/Skill 等辅助: 跳过
    """
    now = datetime.now().strftime("%H:%M")
    short_name = tool_name.split("__")[-1] if "__" in tool_name else tool_name

    # --- 跳过的工具 ---
    _SKIP_TOOLS = frozenset({
        "Read", "Glob", "Grep", "Write", "Edit", "TodoWrite", "Skill",
        "WebSearch", "WebFetch", "EnterPlanMode", "ExitPlanMode",
        "AskUserQuestion", "NotebookEdit", "LSP",
    })
    if short_name in _SKIP_TOOLS:
        return []

    # 子代理的 UI 工具跳过
    _SUBAGENT_SKIP_UI = frozenset({
        "click", "take_snapshot", "take_screenshot", "hover", "press_key",
        "type_text", "drag", "upload_file", "list_pages", "select_page",
        "close_page", "resize_page", "handle_dialog", "wait_for", "emulate",
        "list_console_messages", "get_console_message",
        "list_network_requests", "get_network_request",
        "new_page",
    })
    if is_subagent and short_name in _SUBAGENT_SKIP_UI:
        return []

    # --- 非子代理的辅助工具也跳过 ---
    if not is_subagent and short_name in _SUBAGENT_SKIP_UI:
        return []

    lines: list[str] = []
    prefix = f"{now} "
    if is_subagent:
        prefix += f"[{subagent_name or 'sub'}] "

    error_mark = " ❌" if is_error else ""

    # --- exec / wss_exec ---
    if short_name in ("exec", "wss_exec"):
        cmd = tool_input.get("command", "")[:120]
        lines.append(f"{prefix}`{short_name}` {cmd}{error_mark}")
        # 结果摘要（去掉 wss 常见的 exit_hint 前缀和 exec 的 Exit Code 行）
        result_text = _extract_result_text(tool_response)
        if result_text:
            # 跳过 wss exit_hint 前缀
            for skip_prefix in ("exit_hint: prompt_returned\n", "exit_hint: timeout\n"):
                if result_text.startswith(skip_prefix):
                    result_text = result_text[len(skip_prefix):].lstrip("\n")
            # 跳过 exec "Exit Code: ...\n\n--- STDOUT ---\n" 前缀
            if result_text.startswith("Exit Code:"):
                stdout_marker = "--- STDOUT ---\n"
                idx = result_text.find(stdout_marker)
                if idx >= 0:
                    result_text = result_text[idx + len(stdout_marker):].lstrip("\n")
            if result_text.strip():
                lines.append(f"  → {result_text.strip()[:150]}")
        return lines

    # --- wss_connect ---
    if short_name == "wss_connect":
        params = {k: v for k, v in tool_input.items() if v}
        lines.append(f"{prefix}`wss_connect` {json.dumps(params, ensure_ascii=False)}{error_mark}")
        result_text = _extract_result_text(tool_response)
        if result_text:
            lines.append(f"  → {result_text[:150]}")
        return lines

    # --- record_key_finding ---
    if short_name == "record_key_finding" or "record_key_finding" in tool_name:
        kind = tool_input.get("kind", "?")
        title = tool_input.get("title", "")[:80]
        lines.append(f"{prefix}`record_key_finding` [{kind}] {title}{error_mark}")
        result_text = _extract_result_text(tool_response)
        if result_text:
            lines.append(f"  → {result_text[:80]}")
        return lines

    # --- Task/Agent 委派 ---
    if short_name in ("Task", "Agent"):
        sub_type = tool_input.get("subagent_type", "")
        desc = tool_input.get("description", "")[:80]
        prompt = tool_input.get("prompt", "")[:150]
        lines.append(f"{prefix}`{short_name}` [{sub_type}] {desc}")
        if prompt:
            lines.append(f"  prompt: {prompt}")
        return lines

    # --- kb_search ---
    if short_name == "kb_search" or "kb_search" in tool_name:
        query = tool_input.get("query", "")[:120]
        lines.append(f"{prefix}`kb_search` {query}")
        return lines

    # --- 子代理的关键操作 ---
    if is_subagent:
        if short_name == "navigate_page":
            url = tool_input.get("url", "")[:120]
            nav_type = tool_input.get("type", "url")
            lines.append(f"{prefix}`navigate_page` [{nav_type}] {url}")
            return lines
        if short_name == "fill_form":
            elements = tool_input.get("elements", [])
            summary = ", ".join(
                f"{e.get('uid', '?')}={e.get('value', '')[:30]}"
                for e in elements[:3]
            )
            lines.append(f"{prefix}`fill_form` {summary}")
            return lines
        if short_name == "fill":
            uid = tool_input.get("uid", "?")
            value = tool_input.get("value", "")[:50]
            lines.append(f"{prefix}`fill` {uid}={value}")
            return lines
        if short_name == "evaluate_script":
            func = tool_input.get("function", "")[:120]
            lines.append(f"{prefix}`evaluate_script` {func}")
            return lines

    # 其他 MCP 工具：记录简要信息
    if tool_name.startswith("mcp__"):
        params_summary = json.dumps(tool_input, ensure_ascii=False)[:100] if tool_input else ""
        lines.append(f"{prefix}`{short_name}` {params_summary}{error_mark}")
        return lines

    # 默认：不记录
    return []


def _detect_tool_error(tool_response: Any) -> bool:
    """判断工具返回是否为错误（共享逻辑：timeline 和 reflection 均使用）。"""
    if isinstance(tool_response, dict):
        if tool_response.get("is_error"):
            return True
        content = tool_response.get("content")
        if isinstance(content, list) and content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else ""
            if text.startswith("Exit Code: "):
                try:
                    code = int(text.split("\n", 1)[0].split(": ", 1)[1])
                    return code != 0
                except (ValueError, IndexError):
                    pass
    elif isinstance(tool_response, list) and tool_response:
        first = tool_response[0]
        if isinstance(first, dict):
            text = first.get("text", "")
            if text.startswith("Exit Code: "):
                try:
                    code = int(text.split("\n", 1)[0].split(": ", 1)[1])
                    return code != 0
                except (ValueError, IndexError):
                    pass
    elif isinstance(tool_response, str):
        return tool_response.startswith("Error") or tool_response.startswith("error")
    return False


def _extract_result_text(tool_response: Any) -> str:
    """从 tool_response 中提取可读文本"""
    if isinstance(tool_response, str):
        return tool_response.strip()
    # MCP 工具直接返回 list 格式: [{"type": "text", "text": "..."}]
    if isinstance(tool_response, list) and tool_response:
        first = tool_response[0]
        if isinstance(first, dict):
            return first.get("text", "").strip()
    if isinstance(tool_response, dict):
        # MCP 工具包装格式: {"content": [{"text": "..."}]}
        content = tool_response.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict):
                return first.get("text", "").strip()
        # 直接 text 字段
        text = tool_response.get("text", "")
        if text:
            return text.strip()
    return ""


def create_pre_tool_use_hook(
    tools_requiring_args: tuple = (),
    allowed_tools: Optional[List[str]] = None,
    disallowed_tools: Optional[List[str]] = None,
    agent_name: str = "claude_sdk",
    reflection_tracker: Optional[ReflectionTracker] = None,
    owner_session_id: Optional[str] = None,
) -> HookCallback:
    """
    创建 PreToolUse Hook 回调函数

    Args:
        tools_requiring_args: 需要参数的工具名称元组
        allowed_tools: 允许的工具列表（如果提供，只允许这些工具）
        disallowed_tools: 禁止的工具列表（如果提供，拒绝这些工具）
        agent_name: Agent 名称（用于记录到 history）
        reflection_tracker: 反思追踪器（如果提供，记录工具调用模式）
        owner_session_id: 拥有者 session_id（可选），用于过滤子代理的工具调用

    Returns:
        符合 HookCallback 签名的异步函数
    """
    # session_id 守卫
    _owner_sid: list[Optional[str]] = [owner_session_id]

    async def pre_tool_use_hook(
        input_data: PreToolUseHookInput,
        tool_use_id: Optional[str],
        context: HookContext,
    ) -> HookJSONOutput:
        tool_name = input_data.get("tool_name", "unknown")
        tool_input = input_data.get("tool_input", {})

        # When `output_format` is enabled, Claude SDK may emit a tool call named
        # "StructuredOutput" to deliver JSON-schema compliant data.
        # This tool must never be blocked by allowlist/denylist.
        is_structured_output = tool_name == "StructuredOutput"

        input_str = (
            json.dumps(tool_input, ensure_ascii=False) if tool_input else "(无参数)"
        )

        # 判断来源：子代理 vs Orchestrator
        # 优先使用 SDK 提供的 agent_id（子代理内触发时存在），fallback 到 session_id 比对
        agent_id = input_data.get("agent_id", "")
        agent_type_name = input_data.get("agent_type", "")
        hook_session_id = input_data.get("session_id", "")
        if _owner_sid[0] is None and hook_session_id:
            _owner_sid[0] = hook_session_id
        is_subagent = bool(agent_id) or bool(
            _owner_sid[0] and hook_session_id and hook_session_id != _owner_sid[0]
        )

        subagent_name = agent_type_name if is_subagent else ""
        source_prefix = format_tool_source_prefix(is_subagent, subagent_name)

        # TodoWrite 格式化日志 + 同步 progress.md
        if tool_name == "TodoWrite":
            todos = tool_input.get("todos", [])
            if todos:
                log_todo_event(todos)
                _sync_todos_to_progress(todos)

        # 记录工具调用模式（用于 ReflectionTracker 重复检测）
        # session_id 守卫：只对 Orchestrator 自身的工具调用记入模式检测
        if reflection_tracker and not is_structured_output:
            if not is_subagent:
                reflection_tracker.record_tool_call(tool_name, tool_input)

        # 拦截 take_screenshot：返回的 base64 图片数据极易超过 SDK 1MB 消息限制导致会话崩溃
        if tool_name.endswith("__take_screenshot"):
            log_tool_event(
                f"拦截 {tool_name}: 图片数据可能超过消息大小限制",
                level=logging.WARNING,
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "take_screenshot 返回的图片数据可能超过 SDK 消息大小限制（1MB）导致会话崩溃。"
                        "请改用 take_snapshot 获取页面结构化快照（包含元素 uid，更适合自动化交互）。"
                        "如果确实需要视觉信息，可用 evaluate_script 执行 JS 提取特定元素内容。"
                    ),
                }
            }

        # --- 文件写入路径修正 ---
        # Write/Edit 的 file_path 如果是相对路径，重定向到当前题目的 work_dir 下
        # 防止文件泄露到 agent-work 根目录
        if tool_name in ("Write", "Edit") and not is_subagent:
            file_path = tool_input.get("file_path", "")
            if file_path and not os.path.isabs(file_path):
                work_dir = _get_current_work_dir_str()
                if work_dir:
                    corrected = os.path.join(work_dir, file_path)
                    log_tool_event(
                        f"路径修正: {file_path} → {corrected}",
                    )
                    updated_input = dict(tool_input)
                    updated_input["file_path"] = corrected
                    return {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "allow",
                            "updatedInput": updated_input,
                        }
                    }

        # 检查文件读取操作（防止大文件/二进制文件浪费 token）
        file_read_reason = check_file_read(tool_name, tool_input)
        if file_read_reason:
            log_tool_event(
                f"拦截文件读取: {tool_input.get('file_path', '')}",
                level=logging.WARNING,
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": file_read_reason,
                }
            }

        # --- Compact 后恢复拦截 ---
        # 读取型工具不拦截（让 agent 可以自由读 progress/findings/hint）
        _READ_TOOLS = frozenset({
            "Read", "Glob", "Grep", "Skill", "TodoWrite",
            "WebFetch", "WebSearch",
        })
        _REQUIRED_READS = _get_compact_recovery_files()
        if (
            reflection_tracker
            and reflection_tracker._compact_deny_remaining > 0
            and not is_subagent
            and not is_structured_output
            and tool_name not in _READ_TOOLS
            and not tool_name.startswith("mcp__chying__kb_search")
            and not tool_name.startswith("mcp__chying__record_key_finding")
        ):
            # 优先检查 ProgressCompiler 的 compact_handoff.md 是否已就绪
            # （与 CLI 摘要并行运行，compact 完成时大概率已就绪）
            handoff_path = _try_get_handoff_path(reflection_tracker)
            if handoff_path:
                log_system_event(
                    "Compact recovery: handoff ready, recommending fast-path"
                )
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            "CONTEXT COMPACTED — AI-compiled session handoff 已就绪。\n"
                            f"1. Read {handoff_path}\n"
                            "此文件包含完整的攻击进度摘要、确认的发现、Dead Ends、"
                            "和推荐的下一步方向。读完即可恢复上下文并继续攻击。"
                        ),
                    }
                }

            # handoff 未就绪，走旧路径：要求逐个读取 progress.md + findings.log
            missing = _REQUIRED_READS - reflection_tracker._compact_confirmed_reads
            ordered_missing = [
                f for f in ("progress.md", "findings.log", "hint.md") if f in missing
            ]
            timeline_path = _get_timeline_path()
            # 用 timeline 的父目录拼出恢复文件的完整路径，避免模型用错 cwd
            work_dir = timeline_path.parent if timeline_path else None
            def _full_path(f: str) -> str:
                if work_dir:
                    return str(work_dir / f)
                return f
            log_system_event(
                f"Compact recovery: denying write-type tool "
                f"(missing reads={missing})"
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "CONTEXT COMPACTED — 攻击历史可能丢失。在继续操作前必须恢复上下文：\n"
                        + "\n".join(
                            f"{i+1}. Read {_full_path(f)}"
                            for i, f in enumerate(ordered_missing)
                        )
                        + "\n\n恢复主文件是 progress.md / findings.log / hint.md（如果存在）。"
                        "\n如果仍需追溯命令来源、环境差异或某个 key 的出处，再按需 Read attack_timeline.md。"
                        "\n注意：attack_timeline.md 中 [分析] 标签内容是模型推断，"
                        "可信度低于工具调用结果和 findings.log。"
                        "\n特别注意：检查之前使用的执行环境（WSS远程终端 vs docker本地），"
                        "通过远程环境获取的凭证/会话可能只在远程网络中有效。"
                    ),
                }
            }

        # 检查工具是否在禁止列表中（内置工具限制）
        if (
            (not is_structured_output)
            and disallowed_tools
            and tool_name in disallowed_tools
        ):
            log_tool_event(
                f"工具 {tool_name} 在禁止列表中，已拒绝", level=logging.WARNING
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"工具 {tool_name} 不允许使用，请使用 MCP 工具完成任务",
                }
            }

        # 检查工具是否在允许列表中
        # 外部 MCP 工具（mcp__ 前缀）已通过 disallowed_tools 控制，不做白名单限制
        if (not is_structured_output) and allowed_tools:
            is_allowed = tool_name in allowed_tools or tool_name.startswith("mcp__")
            if not is_allowed:
                log_tool_event(
                    f"工具 {tool_name} 不在允许列表中，已拒绝",
                    level=logging.WARNING,
                )
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"工具 {tool_name} 不在允许列表中",
                    }
                }

        # 验证需要参数的工具
        if (not is_structured_output) and tools_requiring_args:
            # 提取实际工具名（去掉 mcp__xxx__ 前缀）
            actual_tool_name = (
                tool_name.split("__")[-1] if "__" in tool_name else tool_name
            )

            if actual_tool_name in tools_requiring_args and not tool_input:
                log_tool_event(
                    f"工具 {tool_name} 参数为空，将被拒绝", level=logging.WARNING
                )
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"工具 {actual_tool_name} 需要参数",
                    }
                }

        # ABANDON 强制执行：Guidance Loop 启用后，阻止 agent 重复已确认的失败方向
        # 豁免基础工具：读取/搜索/计划类工具不应被阻止，agent 需要它们恢复上下文和调整策略
        _ABANDON_EXEMPT_TOOLS = frozenset({
            "Read", "Glob", "Grep", "WebSearch", "WebFetch",
            "TodoWrite", "Skill", "Agent", "Task",
        })
        _ABANDON_EXEMPT_MCP_PREFIXES = (
            "mcp__chying__kb_search",
            "mcp__chying__record_key_finding",
            "mcp__chying__view_hint",
            "mcp__chying__submit_flag",       # flag 提交是终极目标，绝不应被阻止
        )
        if (
            reflection_tracker
            and reflection_tracker._abandon_active
            and not is_subagent
            and not is_structured_output
            and tool_name not in _ABANDON_EXEMPT_TOOLS
            and not any(tool_name.startswith(p) for p in _ABANDON_EXEMPT_MCP_PREFIXES)
        ):
            abandon_reason = _matches_dead_end(tool_name, tool_input, reflection_tracker)
            if abandon_reason:
                reflection_tracker._metrics_abandon_block_count += 1
                log_tool_event(
                    f"ABANDON block: {tool_name} 匹配 Dead End: {abandon_reason}",
                    level=logging.WARNING,
                )
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"此操作匹配已确认的失败方向 ({abandon_reason})，系统已禁止重试。"
                            "请尝试完全不同的工具或方法。"
                            "阅读 progress.md 的 Attack Tree 寻找未探索的方向。"
                        ),
                    }
                }

        # ── Same-class streak L2 deny（控制平面 Phase 1）──
        if (
            reflection_tracker
            and not is_subagent
            and not is_structured_output
        ):
            streak_deny = reflection_tracker.check_streak_l2(tool_name, tool_input)
            if streak_deny:
                reflection_tracker._metrics_l2_deny_count += 1
                log_tool_event(
                    f"Streak L2 deny: {tool_name}",
                    level=logging.WARNING,
                )
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": streak_deny,
                    }
                }

        return {}

    return cast(HookCallback, pre_tool_use_hook)


def create_post_tool_use_hook(
    agent_name: str = "claude_sdk",
    reflection_tracker: Optional[ReflectionTracker] = None,
    owner_session_id: Optional[str] = None,
    skill_hints: Optional[str] = None,
) -> HookCallback:
    """
    创建 PostToolUse Hook 回调函数

    Args:
        agent_name: Agent 名称（用于记录到 history）
        reflection_tracker: 反思追踪器（可选），用于检测停滞并标记反思
        owner_session_id: 拥有者 session_id（可选），用于过滤子代理的工具调用。
            仅对 session_id 匹配的工具调用进行停滞检测。None 表示不过滤。
        skill_hints: Skill 名称+描述提示文本（可选），在 synthesis checkpoint 时附带提醒

    Returns:
        符合 HookCallback 签名的异步函数
    """
    # 使用可变容器持有 owner_session_id，支持自动检测
    # 首次工具调用时自动记录为 owner session_id（第一次一定是 Orchestrator 自己的）
    _owner_sid: list[Optional[str]] = [owner_session_id]

    async def post_tool_use_hook(
        input_data: PostToolUseHookInput,
        tool_use_id: Optional[str],
        context: HookContext,
    ) -> HookJSONOutput:
        # 提取工具名、输入参数和结果
        tool_name = input_data.get("tool_name", "unknown")
        tool_input = input_data.get("tool_input", {})
        # SDK 文档使用 tool_response 字段名
        tool_response = input_data.get("tool_response", "")

        # 转换结果为字符串（用于日志）
        if isinstance(tool_response, dict):
            result_str = json.dumps(tool_response, ensure_ascii=False)
        elif isinstance(tool_response, str):
            result_str = tool_response
        else:
            result_str = str(tool_response)

        # 判断来源：子代理 vs Orchestrator
        # 优先使用 SDK 提供的 agent_id（子代理内触发时存在），fallback 到 session_id 比对
        agent_id = input_data.get("agent_id", "")
        agent_type_name = input_data.get("agent_type", "")
        hook_session_id = input_data.get("session_id", "")
        if _owner_sid[0] is None and hook_session_id:
            _owner_sid[0] = hook_session_id
        is_subagent = bool(agent_id) or bool(
            _owner_sid[0] and hook_session_id and hook_session_id != _owner_sid[0]
        )

        subagent_name = agent_type_name if is_subagent else ""
        source_prefix = format_tool_source_prefix(is_subagent, subagent_name)

        # --- Timeline 自动记录 ---
        # 在所有 early return 之前记录，确保 Task/Agent 委派等也被捕获
        try:
            _tl_is_error = _detect_tool_error(tool_response)
            timeline_path = _get_timeline_path()
            if timeline_path:
                entries = _format_timeline_entry(
                    tool_name, tool_input, tool_response,
                    _tl_is_error, is_subagent, subagent_name,
                )
                for entry in entries:
                    _append_timeline(timeline_path, entry)
        except Exception:
            pass

        # --- Compact 恢复状态追踪 ---
        # 记录成功读取的恢复文件，全部读完后退出恢复模式（解锁写操作）
        _RECOVERY_FILES = _get_compact_recovery_files()
        try:
            if (
                tool_name == "Read"
                and not is_subagent
                and reflection_tracker
                and reflection_tracker._compact_deny_remaining > 0
                and not _detect_tool_error(tool_response)  # 只统计成功的 Read
            ):
                file_path = tool_input.get("file_path", "") if isinstance(tool_input, dict) else ""

                # 快速通道：读了 compact_handoff.md 等效于读了所有 recovery 文件
                if file_path.endswith("compact_handoff.md"):
                    reflection_tracker._compact_confirmed_reads = set(_RECOVERY_FILES)
                    reflection_tracker._compact_deny_remaining = 0
                    log_system_event(
                        "Compact recovery fast-path: compact_handoff.md read, "
                        "skipping individual file recovery"
                    )
                else:
                    # 正常通道：逐文件确认
                    matched = next(
                        (f for f in _RECOVERY_FILES if file_path.endswith(f"/{f}") or file_path == f),
                        None,
                    )
                    if matched:
                        reflection_tracker._compact_confirmed_reads.add(matched)
                        if _RECOVERY_FILES <= reflection_tracker._compact_confirmed_reads:
                            reflection_tracker._compact_deny_remaining = 0
                            log_system_event("Compact recovery complete: all required files read, resuming normal operation")
        except Exception:
            pass

        # ── 控制平面 Phase 1: 统一收集 → 单次返回（去除 Task/Agent early-return）──

        # 1. Task/Agent findings + YAML 摘要提取（不 early-return）
        _task_agent_findings: Optional[str] = None
        _yaml_summary_ctx: Optional[str] = None
        yaml_data: Optional[dict] = None
        if tool_name in ("Task", "Agent") and not is_subagent:
            _task_agent_findings = _read_subagent_findings()
            # §1.4 Phase 2: YAML 结构化摘要提取
            yaml_data = _extract_subagent_yaml(result_str or "")
            if yaml_data and reflection_tracker:
                reflection_tracker._metrics_yaml_parse_ok += 1
                # 记录 stop_reason
                sr = yaml_data.get("stop_reason")
                if sr:
                    reflection_tracker._metrics_stop_reasons.append(str(sr))
                # 存入 ReflectionTracker 供 guidance query 消费 stop_reason
                reflection_tracker._last_subagent_yaml = yaml_data
                # 提取 highest_anomaly 和 new_findings 注入 orchestrator
                parts = []
                high_value_titles: list[str] = []
                high_value_keywords = (
                    "credential", "credentials", "session", "cookie", "token",
                    "secret", "flag", "shell", "wss", "websocket", "tty",
                    "aws", "access key",
                )
                anomaly = yaml_data.get("highest_anomaly")
                if anomaly and anomaly != "null":
                    parts.append(f"🔍 子代理最高优先异常: {anomaly}")
                    parts.append(
                        "⚠️ 父代理下一步必须优先验证并跟进该异常，"
                        "在验证完成前不要切回无关的旁路线索或 sibling 枚举。"
                    )
                new_findings = yaml_data.get("new_findings")
                if isinstance(new_findings, list) and new_findings:
                    findings_lines = []
                    for f in new_findings[:5]:
                        if isinstance(f, dict):
                            title = str(f.get("title", "?"))
                            status = str(f.get("status", "?"))
                            findings_lines.append(
                                f"  - {title} (status: {status})"
                            )
                            title_lower = title.lower()
                            if (
                                status in ("confirmed", "exploited")
                                or any(kw in title_lower for kw in high_value_keywords)
                            ):
                                high_value_titles.append(title)
                    if findings_lines:
                        parts.append("子代理新发现:\n" + "\n".join(findings_lines))
                if high_value_titles:
                    deduped_titles: list[str] = []
                    for title in high_value_titles:
                        if title not in deduped_titles:
                            deduped_titles.append(title)
                    parts.append(
                        "⚠️ 检测到高价值子代理结果。下一步必须先消费这些结果并沿同一方向推进，"
                        "在完成验证前禁止回到无关的 sibling API/路径/资源枚举：\n"
                        + "\n".join(f"  - {title}" for title in deduped_titles[:5])
                    )
                if parts:
                    _yaml_summary_ctx = "\n".join(parts)
            elif yaml_data is None and reflection_tracker:
                reflection_tracker._metrics_yaml_parse_fail += 1
                _yaml_summary_ctx = (
                    "⚠️ 子代理未按格式返回结构化摘要。"
                    "请主动追问关键发现和建议。"
                )
            # 无论 reflection tracker 是否启用，都尽早把子代理最新状态刷入 progress.md
            _sync_subagent_result_to_progress(
                tool_name, tool_input, yaml_data, result_str
            )

        # 2. 子代理的工具调用，不参与停滞检测（保留原有行为）
        if reflection_tracker and is_subagent:
            return {}

        # 3. 主循环：反思检测 + 控制平面信号
        if reflection_tracker and not is_subagent:
            # R8: view_hint 重置
            if "view_hint" in tool_name:
                reflection_tracker.apply_view_hint_reset()
                reflection_tracker._metrics_view_hint_count += 1
            # R9: stagnation-recovery Skill 重置
            if tool_name == "Skill" and tool_input:
                if "stagnation-recovery" in str(tool_input.get("skill", "")):
                    reflection_tracker.apply_stagnation_recovery_reset()

            is_error = _detect_tool_error(tool_response)
            action = reflection_tracker.on_tool_result(
                tool_name, is_error, result_str, tool_input=tool_input
            )

            short = tool_name.split("__")[-1] if "__" in tool_name else tool_name
            is_non_ui = (
                short not in ReflectionTracker._BROWSER_UI_TOOLS
                or reflection_tracker._last_result_was_terminal_eval
            )

            # Bucket streak 递增 + checkpoint buffer（仅非 UI 工具）
            if is_non_ui:
                reflection_tracker.classify_and_increment(tool_name, tool_input)
                reflection_tracker.record_checkpoint_entry(
                    tool_name, tool_input,
                    "ERR" if is_error else "OK",
                    (result_str or "")[:100],
                )

            # 收集所有 additionalContext 片段
            additional_parts: list[str] = []

            if _task_agent_findings:
                additional_parts.append(_task_agent_findings)
            if _yaml_summary_ctx:
                additional_parts.append(_yaml_summary_ctx)

            # ── Pivot 自动提醒：检测到内网网段/多层网络发现时注入 ──
            # 注意：仅在发现内网目标时触发，不在简单 RCE 时触发（大多数题 RCE 后直接读 flag）
            _pivot_network_keywords = (
                "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                "192.168.", "10.0.", "10.10.",
                "内网", "内部网络", "internal network",
                "docker network", "subnet", "网段", "lateral", "横向",
                "pivot", "跳板", "多层", "multi-layer",
            )
            _pivot_hint_text = (
                "🔄 PIVOT HINT: 发现内网/多层网络目标。如果当前主机的 flag 已拿完但题目还有未解 flag：\n"
                "1. Skill(\"infra-exploit\") §7 — webshell 升级 → tunnel 建立 → 内网渗透\n"
                "2. 建 tunnel（chisel/frp/SSH）后用 proxychains + fscan 批量扫内网\n"
                "3. 需要 Metasploit 交互 → Task[c2]"
            )
            _pivot_injected = False
            # 来源 1: record_key_finding 提到内网网段
            if (
                "record_key_finding" in tool_name
                and not is_error
                and result_str
            ):
                _lower_result = result_str.lower()
                if any(kw in _lower_result for kw in _pivot_network_keywords):
                    additional_parts.append(_pivot_hint_text)
                    _pivot_injected = True
            # 来源 2: 子代理 YAML findings 提到内网网段
            if not _pivot_injected and _yaml_summary_ctx:
                _lower_yaml = _yaml_summary_ctx.lower()
                if any(kw in _lower_yaml for kw in _pivot_network_keywords):
                    additional_parts.append(_pivot_hint_text)

            if action == ReflectionAction.SOFT_WARN:
                reason_text, context_text = build_soft_warning_text(reflection_tracker)
                log_system_event(
                    f"[{agent_name}] Stagnation detected: soft warning triggered"
                )
                additional_parts.append(f"{reason_text}\n\n{context_text}")
                # Hint 提醒 level 1（随 SOFT_WARN 触发）
                hint = reflection_tracker.check_hint_reminder(is_soft_warn=True)
                if hint:
                    additional_parts.append(hint)

            elif action == ReflectionAction.HARD_REFLECT:
                reflection_tracker._abandon_active = True
                log_system_event(
                    f"[{agent_name}] Stagnation persists: ABANDON enforcement activated "
                    f"(#{reflection_tracker.reflection_count})"
                )
                additional_parts.append(
                    "STAGNATION CONFIRMED -- ABANDON enforcement is now active. "
                    "The system will block tool calls that match known Dead Ends. "
                    "You MUST switch to a fundamentally different approach. "
                    "Read progress.md to find unexplored directions in the Attack Tree."
                )

            elif is_non_ui:
                # Streak L1 软提醒
                streak_warn = reflection_tracker.get_streak_l1_warning()
                if streak_warn:
                    additional_parts.append(streak_warn)

                # Hint 提醒 level 2（8+ 次操作后仍无进展）
                hint = reflection_tracker.check_hint_reminder(is_soft_warn=False)
                if hint:
                    additional_parts.append(hint)

                # §1.5 Finding 提醒（25 次无 record_key_finding，一次性）
                finding_remind = reflection_tracker.check_finding_reminder()
                if finding_remind:
                    additional_parts.append(finding_remind)

                # 现有 reminders（仅在没有控制平面信号时触发）
                if not streak_warn and not hint and not finding_remind:
                    reminder = reflection_tracker.consume_post_reflection_reminder()
                    if reminder:
                        additional_parts.append(reminder)
                    else:
                        synthesis = reflection_tracker.check_synthesis_reminder()
                        if synthesis:
                            if skill_hints:
                                synthesis += skill_hints
                            additional_parts.append(synthesis)
                        else:
                            progress = reflection_tracker.check_progress_reminder()
                            if progress:
                                additional_parts.append(progress)
            else:
                # UI 工具：仅 skill hints
                if skill_hints and reflection_tracker.check_skill_hint_reminder():
                    additional_parts.append(
                        "SKILL REMINDER: Review available skills that may help with your current approach.\n"
                        + skill_hints
                    )

            # Auto checkpoint 写入
            if is_non_ui and reflection_tracker.should_write_checkpoint():
                entries, cp_num = reflection_tracker.consume_checkpoint_buffer()
                _write_checkpoint(entries, cp_num)

            if additional_parts:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PostToolUse",
                        "additionalContext": "\n\n".join(additional_parts),
                    }
                }

        elif _task_agent_findings:
            # reflection_tracker 为 None 但有 Task/Agent findings
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": _task_agent_findings,
                }
            }

        return {}

    return cast(HookCallback, post_tool_use_hook)


def create_subagent_stop_hook(
    agent_name: str = "claude_sdk",
) -> HookCallback:
    """
    创建 SubagentStop Hook 回调函数

    当子代理（通过 Task 工具调用）完成时触发。
    仅做日志记录。上下文注入由 PostToolUse hook 在 Task/Agent 工具完成时处理
    （SubagentStop 不支持 additionalContext -- SDK 未定义对应 HookSpecificOutput）。

    Args:
        agent_name: Agent 名称（用于日志前缀）

    Returns:
        符合 HookCallback 签名的异步函数
    """

    async def subagent_stop_hook(
        input_data: SubagentStopHookInput,
        tool_use_id: Optional[str],
        context: HookContext,
    ) -> HookJSONOutput:
        agent_id = input_data.get("agent_id", "")
        agent_type = input_data.get("agent_type", "")
        agent_transcript_path = input_data.get("agent_transcript_path", "")
        hook_session_id = input_data.get("session_id", "")

        log_system_event(
            f"[{agent_name}] SubagentStop",
            {
                "agent_id": agent_id,
                "agent_type": agent_type,
                "hook_session_id": hook_session_id,
                "agent_transcript_path": agent_transcript_path,
            },
        )

        return {}

    return cast(HookCallback, subagent_stop_hook)
