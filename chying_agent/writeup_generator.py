"""
Writeup 自动生成模块
===================

提供 writeup 上下文构建和生成功能，供 challenge_solver（自动）和 web API（手动）调用。

信息来源全部为工作目录下的文件（dumps/execution_summary.md、findings.log 等），
DB 仅用于保存生成结果。
"""

import logging
import os
from pathlib import Path
from typing import Optional

from chying_agent.db.recorder import recorder

logger = logging.getLogger(__name__)


def build_writeup_context(work_dir: Path, challenge_info: dict) -> str:
    """从工作目录文件构建 writeup 生成上下文

    Args:
        work_dir: 题目工作目录
        challenge_info: 题目元信息 dict，至少包含 challenge_code，
            可选 mode, difficulty, points, target_url, target_ip, hint_content, flag

    Returns:
        构建好的上下文字符串
    """
    code = challenge_info.get("challenge_code", "unknown")
    parts = [
        f"# Challenge: {code}",
        f"- Mode: {challenge_info.get('mode', 'unknown')}",
        f"- Difficulty: {challenge_info.get('difficulty', 'unknown')}",
        f"- Points: {challenge_info.get('points', 0)}",
    ]
    if challenge_info.get("target_url"):
        parts.append(f"- Target URL: {challenge_info['target_url']}")
    if challenge_info.get("target_ip"):
        parts.append(f"- Target IP: {challenge_info['target_ip']}")
    if challenge_info.get("hint_content"):
        parts.append(f"- Hint: {challenge_info['hint_content']}")
    if challenge_info.get("flag"):
        parts.append(f"- Flag: {challenge_info['flag']}")

    # --- 从 progress.md 读取攻击计划和关键发现 ---
    progress_file = work_dir / "progress.md"
    if progress_file.exists():
        try:
            content = progress_file.read_text(encoding="utf-8").strip()
            if content:
                parts.append("\n## Progress (progress.md)")
                parts.append(content)
        except Exception as e:
            parts.append(f"(Failed to read progress.md: {e})")

    # --- 从 execution_summary.md 读取执行摘要 ---
    summary_file = work_dir / "dumps" / "execution_summary.md"
    if summary_file.exists():
        try:
            content = summary_file.read_text(encoding="utf-8").strip()
            if content:
                parts.append("\n## Execution Summary")
                parts.append(content)
        except Exception as e:
            parts.append(f"(Failed to read execution_summary.md: {e})")

    # --- 从 findings.log 读取关键发现 ---
    memory_file = work_dir / "findings.log"
    if memory_file.exists():
        try:
            content = memory_file.read_text(encoding="utf-8").strip()
            if content:
                parts.append("\n## Discoveries (findings.log)")
                parts.append(content)
        except Exception as e:
            parts.append(f"(Failed to read findings.log: {e})")

    # --- 从 commands.log 读取命令执行记录 ---
    commands_file = work_dir / "dumps" / "commands.log"
    if commands_file.exists():
        try:
            content = commands_file.read_text(encoding="utf-8").strip()
            if content:
                parts.append("\n## Commands Log (commands.log)")
                parts.append(content)
        except Exception as e:
            parts.append(f"(Failed to read commands.log: {e})")

    # --- 列出 poc_scripts/ 目录中的脚本文件 ---
    poc_dir = work_dir / "poc_scripts"
    if poc_dir.is_dir():
        poc_files = sorted(poc_dir.glob("*"))
        if poc_files:
            parts.append("\n## PoC Scripts (poc_scripts/)")
            parts.append(f"Work directory: {work_dir}")
            parts.append("Available scripts (use Read tool to get full content):")
            for f in poc_files:
                if f.is_file():
                    parts.append(f"- {f.name} ({f.stat().st_size} bytes)")

    return "\n".join(parts)


async def generate_writeup(
    work_dir: Path,
    challenge_info: dict,
    challenge_db_id: Optional[int] = None,
) -> Optional[str]:
    """生成 writeup 并保存到 DB 和工作目录

    Args:
        work_dir: 题目工作目录
        challenge_info: 题目元信息 dict（传给 build_writeup_context）
        challenge_db_id: 题目 DB ID（可选，用于 DB 保存）

    Returns:
        生成的 writeup markdown 内容，失败返回 None
    """
    from chying_agent.claude_sdk import BaseClaudeAgent
    from chying_agent.agents.writeup_agent import WRITEUP_AGENT_SYSTEM_PROMPT

    context = build_writeup_context(work_dir, challenge_info)

    class WriteupGenerator(BaseClaudeAgent):
        def _get_agent_type(self) -> str:
            return "WriteupGenerator"

        def _get_mcp_servers(self) -> None:
            return None

        def _get_allowed_tools(self) -> list[str]:
            return ["Read", "Glob", "Grep"]

        def _get_disallowed_tools(self) -> list[str]:
            return ["Bash", "Write", "Edit", "Task"]

    code = challenge_info.get("challenge_code", "unknown")

    try:
        generator = WriteupGenerator(
            model=os.getenv("LLM_MODEL"),
            system_prompt=WRITEUP_AGENT_SYSTEM_PROMPT,
            max_turns=10,
            api_key=os.getenv("LLM_API_KEY"),
            base_url=os.getenv("LLM_BASE_URL"),
        )

        result = await generator.execute(
            f"请根据以下信息生成一份详细的 Writeup 报告（Markdown 格式）。\n"
            f"要求：每个步骤必须包含具体操作、实际结果、技术原理，让初学者也能看懂并复现。\n"
            f"如果上下文提到了 poc_scripts/ 目录，请用 Read 工具读取最终版本的脚本代码。\n\n"
            f"{context}"
        )

        content_markdown = ""
        if result and result.get("success"):
            content_markdown = result.get("response", "")

        if not content_markdown.strip():
            logger.warning(f"[Writeup] 生成内容为空: {code}")
            return None

        # 保存到 DB（如果有 challenge_db_id）
        if challenge_db_id and challenge_db_id > 0:
            writeup_id = recorder.record_writeup(challenge_db_id, content_markdown)
            if writeup_id:
                logger.info(f"[Writeup] 已保存到 DB: writeup_id={writeup_id}")
            else:
                logger.warning(f"[Writeup] DB 保存失败: {code}")

        # 写入工作目录
        try:
            writeup_file = work_dir / "writeup.md"
            writeup_file.write_text(content_markdown, encoding="utf-8")
            logger.info(f"[Writeup] 已写入文件: {writeup_file}")
        except Exception as e:
            logger.warning(f"[Writeup] 写入文件失败: {e}")

        return content_markdown

    except Exception as e:
        logger.exception(f"[Writeup] 生成失败: {code}, error={e}")
        return None
