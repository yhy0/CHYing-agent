"""\
Retry Handoff Compiler
======================

重做续作编译器：当检测到题目被重试时，读取历史工作目录下的所有日志，
合成结构化的续作报告（retry_handoff.md），清理冗余文件后注入新会话。

设计原则：
- 基于 ProgressCompiler 模式，只读工具 + 纯文本输出
- 核心文件（findings.log, execution_summary.md）直接注入 prompt
- 大文件（progress.md, attack_timeline.md, challenge logs）传路径让 agent Grep
- 输出比 compact_handoff 更详细（~3000 tokens），包含完整复现步骤
- 失败时静默降级，调用方 fallback 到原 _build_prior_knowledge 路径
"""

import logging
import os
from pathlib import Path
from typing import Optional, Any, Dict, List

from ..claude_sdk import BaseClaudeAgent
from ..common import log_system_event
from ..utils.path_utils import get_host_agent_work_dir
from ..prompts import load_prompt

# 系统 prompt 从 .md 文件加载
_RETRY_HANDOFF_SYSTEM_PROMPT = load_prompt("retry_handoff.md")

# 编译没有硬超时——max_turns=10 是自然终止条件。
# 重做续作是做题前的关键前置步骤，宁可多花几分钟编译出高质量报告，
# 也不要降级到读 50KB 膨胀文件。

# 预注入文件的最大字符数
_MAX_INPUT_CHARS = 80_000


class RetryHandoffCompiler(BaseClaudeAgent):
    """重做时编译历史信息为精炼的续作报告。

    读取 findings.log、execution_summary、hint 等核心文件，
    结合 progress.md / attack_timeline / challenge logs 的 Grep 结果，
    生成包含完整攻击链复现步骤的 retry_handoff.md。
    """

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        _model = model or os.getenv("LLM_MODEL") or None
        _api_key = api_key or os.getenv("LLM_API_KEY") or None
        _base_url = base_url or os.getenv("LLM_BASE_URL") or None
        _cwd = str(get_host_agent_work_dir())

        super().__init__(
            model=_model,
            system_prompt=_RETRY_HANDOFF_SYSTEM_PROMPT,
            max_turns=10,
            enable_hooks=True,  # 需要 file_guards 拦截大文件读取，防止 context 爆
            cwd=_cwd,
            api_key=_api_key,
            base_url=_base_url,
            persistent_session=False,
            sandbox_enabled=False,
            setting_sources=["project"],
        )

    def _get_agent_type(self) -> str:
        return "RetryHandoffCompiler"

    def _get_mcp_servers(self) -> Optional[Dict[str, Dict[str, Any]]]:
        return None

    def _get_allowed_tools(self) -> List[str]:
        return ["Read", "Grep", "Glob"]

    def _get_output_schema(self) -> Optional[Dict[str, Any]]:
        return None

    async def compile(
        self,
        work_dir: Path,
        challenge_code: str = "",
        log_dir: Optional[Path] = None,
    ) -> Optional[Path]:
        """读取工作目录历史数据，生成 retry_handoff.md。

        Args:
            work_dir: challenge 工作目录
            challenge_code: 题目 ID（用于匹配历史日志）
            log_dir: challenge 日志目录（logs/challenges/）

        Returns:
            retry_handoff.md 的 Path（若成功），否则 None。
        """
        handoff_path = work_dir / "retry_handoff.md"

        # ---- Phase 1: Python 预读核心文件 ----
        file_contents: List[str] = []
        total_chars = 0

        # 小文件：直接注入 prompt
        small_files = [
            ("findings.log", work_dir / "findings.log"),
            ("dumps/execution_summary.md", work_dir / "dumps" / "execution_summary.md"),
            ("hint.md", work_dir / "hint.md"),
            ("dumps/reflection_history.md", work_dir / "dumps" / "reflection_history.md"),
        ]
        for label, fpath in small_files:
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace").strip()
                if not content:
                    continue
                remaining = _MAX_INPUT_CHARS - total_chars
                if remaining <= 0:
                    break
                if len(content) > remaining:
                    content = content[:remaining] + "\n... [truncated]"
                file_contents.append(f"=== {label} ===\n{content}")
                total_chars += len(content)
            except Exception:
                continue

        if not file_contents:
            log_system_event(
                "[RetryHandoffCompiler] 无可用输入文件",
                {"work_dir": str(work_dir)},
                level=logging.WARNING,
            )
            return None

        # ---- Phase 2: 大文件路径（供 Grep） ----
        large_file_hints: List[str] = []

        # progress.md
        progress_path = work_dir / "progress.md"
        if progress_path.exists():
            size_kb = progress_path.stat().st_size // 1024
            large_file_hints.append(
                f"- `{progress_path}` ({size_kb}KB) — Contains attack tree, dead ends, "
                f"compiled task context. Use Grep for specific sections."
            )

        # attack_timeline.md
        timeline_path = work_dir / "attack_timeline.md"
        if timeline_path.exists():
            size_kb = timeline_path.stat().st_size // 1024
            large_file_hints.append(
                f"- `{timeline_path}` ({size_kb}KB) — Chronological tool call log. "
                f"Grep for specific commands or error messages."
            )

        # 历史 challenge 日志
        if log_dir and challenge_code:
            log_files = sorted(log_dir.glob(f"{challenge_code}_*.log"))
            if log_files:
                large_file_hints.append(
                    f"- Challenge logs directory: `{log_dir}/`\n"
                    f"  Pattern: `{challenge_code}_*.log` ({len(log_files)} files found)\n"
                    f"  These contain FULL tool call outputs and results from ALL prior sessions.\n"
                    f"  **findings.log may be incomplete** — use Grep on these logs to find "
                    f"additional findings, credentials, flags, and error details.\n"
                    f"  Use `Glob(\"{log_dir}/{challenge_code}_*.log\")` to list them, "
                    f"then Grep specific ones for keywords like 'flag', 'credential', 'shell', 'exploit'.\n"
                    f"  Do NOT Read entire log files — they are very large. Always use Grep."
                )

        # poc_scripts 列表
        poc_dir = work_dir / "poc_scripts"
        if poc_dir.exists():
            large_file_hints.append(
                f"- `{poc_dir}/` — Contains exploit scripts. "
                f"Use Glob to list, Read specific scripts if needed."
            )

        large_files_section = ""
        if large_file_hints:
            large_files_section = (
                "\n## Large Files (use Grep only, do NOT Read entire files)\n"
                + "\n".join(large_file_hints)
                + "\n"
            )

        # ---- Phase 3: 构建 prompt ----
        message = (
            "This challenge has been attempted before and timed out/failed. "
            "Analyze ALL the provided data and generate a comprehensive "
            "Retry Handoff Report.\n\n"
            "RULES:\n"
            "1. If the logs below are sufficient, output the report directly.\n"
            "2. Use Grep on large files only if you need specific details not in the injected data.\n"
            "3. Replace external target IPs with TARGET_IP. Keep internal IPs (172.x, 192.168.x) as-is.\n"
            "4. Your FINAL message must be the report markdown, starting with '## Retry Handoff Report'.\n"
            f"{large_files_section}\n"
            "## Injected Core Data\n\n"
            + "\n\n".join(file_contents)
        )

        try:
            result = await self.execute(message)

            if not result.get("success"):
                log_system_event(
                    "[RetryHandoffCompiler] 执行失败",
                    {"error": result.get("error", "unknown")},
                    level=logging.WARNING,
                )
                return None

            # ---- Phase 4: 提取输出写文件 ----
            output_text = result.get("response", "")
            if not output_text or len(output_text.strip()) < 100:
                log_system_event(
                    "[RetryHandoffCompiler] 模型输出为空或过短",
                    {"output_len": len(output_text) if output_text else 0},
                    level=logging.WARNING,
                )
                return None

            content = output_text.strip()
            marker = "## Retry Handoff Report"
            idx = content.find(marker)
            if idx > 0:
                content = content[idx:]

            handoff_path.write_text(content, encoding="utf-8")

            content_len = handoff_path.stat().st_size
            log_system_event(
                "[RetryHandoffCompiler] 编译成功",
                {"handoff_path": str(handoff_path), "bytes": content_len},
            )
            return handoff_path

        except Exception as e:
            log_system_event(
                f"[RetryHandoffCompiler] 异常: {e}",
                level=logging.WARNING,
            )
            return None


async def run_retry_handoff(
    work_dir: Path,
    challenge_code: str = "",
    log_dir: Optional[Path] = None,
) -> Optional[Path]:
    """运行 RetryHandoffCompiler，无超时限制。

    重做续作是做题前的关键前置步骤，max_turns=10 是自然终止条件。
    宁可多花几分钟编译出高质量报告，也不要降级到读膨胀文件。

    Args:
        work_dir: challenge 工作目录
        challenge_code: 题目 ID
        log_dir: challenge 日志目录

    Returns:
        retry_handoff.md 的 Path（成功），否则 None
    """
    log_system_event(
        "[RetryHandoffCompiler] 启动（重做续作编译）",
        {"work_dir": str(work_dir), "challenge_code": challenge_code},
    )
    try:
        compiler = RetryHandoffCompiler()
        return await compiler.compile(
            work_dir, challenge_code=challenge_code, log_dir=log_dir,
        )
    except Exception as e:
        log_system_event(
            f"[RetryHandoffCompiler] 异常: {e}",
            level=logging.WARNING,
        )
        return None


def cleanup_work_dir_for_retry(work_dir: Path) -> None:
    """清理工作目录中的冗余文件，保留精炼数据。

    在 RetryHandoffCompiler 成功生成 retry_handoff.md 后调用。
    删除膨胀的原始日志，保留结构化数据和可复用资源。
    """
    # 需要删除的文件（膨胀的、已被 handoff 编译消化的）
    files_to_delete = [
        "progress.md",              # 75% checkpoint 垃圾，精华已在 handoff
        "attack_timeline.md",       # 多次重试累积的命令日志
        "compact_handoff.md",       # 旧 session 的 compact 产物
    ]
    dirs_to_clean = {
        "dumps": [
            "checkpoints.log",      # 与 timeline 重叠
            "commands.log",         # 已提取到 handoff
        ],
    }

    for fname in files_to_delete:
        fpath = work_dir / fname
        if fpath.exists():
            try:
                fpath.unlink()
                log_system_event(f"[RetryCleanup] 删除: {fname}")
            except Exception as e:
                log_system_event(
                    f"[RetryCleanup] 删除失败 {fname}: {e}",
                    level=logging.WARNING,
                )

    for dirname, filenames in dirs_to_clean.items():
        for fname in filenames:
            fpath = work_dir / dirname / fname
            if fpath.exists():
                try:
                    fpath.unlink()
                    log_system_event(f"[RetryCleanup] 删除: {dirname}/{fname}")
                except Exception as e:
                    log_system_event(
                        f"[RetryCleanup] 删除失败 {dirname}/{fname}: {e}",
                        level=logging.WARNING,
                    )

    # 保留：retry_handoff.md, findings.log, hint.md, poc_scripts/,
    #        dumps/execution_summary.md, dumps/reflection_history.md
