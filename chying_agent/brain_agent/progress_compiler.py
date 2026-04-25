"""\
Progress Compiler
=================

上下文压缩后的进度恢复代理：读取工作目录下的原始日志，
合成结构化的接手文档（compact_handoff.md），供新会话注入使用。

设计原则（v3）：
- 主要输入（progress.md + findings.log）直接注入 prompt，确保模型一定能看到
- 模型可用 Read/Grep 工具查原始日志（challenge log），按需 grep 细节
- 模型不调用 Write——输出纯文本，由 Python 代码写文件
- max_turns=3：1 轮直接输出 or 1-2 轮 grep 补查 + 1 轮输出
- 失败时静默降级，调用方 fallback 到旧路径读 progress.md + findings.log
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
_PROGRESS_COMPILER_SYSTEM_PROMPT = load_prompt("progress_compiler.md")

# compact_handoff 编译没有硬超时——max_turns 是自然终止条件。
# 压缩编译是做题恢复的关键前置步骤，必须等完成才能继续做题。

# 预注入文件的最大字符数（~17K tokens，留空间给模型输出和 grep 结果）
_MAX_INPUT_CHARS = 60_000


class ProgressCompiler(BaseClaudeAgent):
    """上下文压缩后的进度恢复代理。

    核心文件（progress.md + findings.log）直接注入 prompt，保证模型一定能看到。
    模型可用 Read/Grep 查原始日志补充细节，但最终输出纯文本，由 Python 写文件。
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
            system_prompt=_PROGRESS_COMPILER_SYSTEM_PROMPT,
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
        return "ProgressCompiler"

    def _get_mcp_servers(self) -> Optional[Dict[str, Dict[str, Any]]]:
        return None

    def _get_allowed_tools(self) -> List[str]:
        # 只读工具：用于按需 grep 原始日志中的细节
        return ["Read", "Grep"]

    def _get_output_schema(self) -> Optional[Dict[str, Any]]:
        return None

    async def compile(
        self,
        work_dir: Path,
        log_file_path: Optional[str] = None,
    ) -> Optional[Path]:
        """读取工作目录日志，生成 compact_handoff.md。

        Args:
            work_dir: challenge 工作目录（含 progress.md / findings.log 等）
            log_file_path: 原始系统日志路径，提供给模型按需 grep

        Returns:
            compact_handoff.md 的 Path（若成功），否则 None。
        """
        handoff_path = work_dir / "compact_handoff.md"

        # ---- Phase 1: Python 预读核心文件，拼入 prompt ----
        file_contents = []
        total_chars = 0

        for filename in ("progress.md", "findings.log"):
            fpath = work_dir / filename
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                remaining = _MAX_INPUT_CHARS - total_chars
                if remaining <= 0:
                    break
                if len(content) > remaining:
                    content = content[:remaining] + "\n... [truncated]"
                file_contents.append(f"=== {filename} ===\n{content}")
                total_chars += len(content)
            except Exception:
                continue

        if not file_contents:
            log_system_event(
                "[ProgressCompiler] 无可用输入文件",
                {"work_dir": str(work_dir)},
                level=logging.WARNING,
            )
            return None

        # ---- Phase 2: 构建 prompt ----
        log_hint = ""
        if log_file_path and log_file_path != "(日志路径未知)":
            log_hint = (
                f"\n## Reference Log (for grep only, do NOT read the whole file)\n"
                f"Path: {log_file_path}\n"
                f"This file contains full tool call outputs and error messages. "
                f"If you need to verify a specific finding's origin or check "
                f"exact error messages, use Grep on this file. "
                f"Do NOT use Read on this file — it's too large.\n"
            )

        message = (
            "Below are the core execution logs from the previous session.\n"
            f"{log_hint}\n"
            "Analyze them and generate the compact_handoff.md content.\n\n"
            "RULES:\n"
            "1. If the logs below are sufficient, output the handoff markdown directly — no tool calls needed.\n"
            "2. If you need to verify a specific detail, use Grep on the reference log path above.\n"
            "3. Do NOT use Read on large files. Do NOT use Write — the caller writes your output.\n"
            "4. Your FINAL message must be the handoff markdown, starting with '## Session Handoff'.\n\n"
            + "\n\n".join(file_contents)
        )

        try:
            result = await self.execute(message)

            if not result.get("success"):
                log_system_event(
                    "[ProgressCompiler] 执行失败",
                    {"error": result.get("error", "unknown")},
                    level=logging.WARNING,
                )
                return None

            # ---- Phase 3: 从模型最终输出中提取内容并写文件 ----
            output_text = result.get("response", "")
            if not output_text or len(output_text.strip()) < 50:
                log_system_event(
                    "[ProgressCompiler] 模型输出为空或过短",
                    {"output_len": len(output_text) if output_text else 0},
                    level=logging.WARNING,
                )
                return None

            # 提取 handoff 内容：从 "## Session Handoff" 开始截取
            content = output_text.strip()
            marker = "## Session Handoff"
            idx = content.find(marker)
            if idx > 0:
                content = content[idx:]

            handoff_path.write_text(content, encoding="utf-8")

            content_len = handoff_path.stat().st_size
            log_system_event(
                "[ProgressCompiler] 编译成功",
                {"handoff_path": str(handoff_path), "bytes": content_len},
            )
            return handoff_path

        except Exception as e:
            log_system_event(
                f"[ProgressCompiler] 异常: {e}",
                level=logging.WARNING,
            )
            return None


async def run_progress_compiler(
    work_dir: Path,
    log_file_path: Optional[str] = None,
) -> Optional[Path]:
    """在 compact 边界运行 ProgressCompiler，无超时限制。

    压缩编译是做题恢复的关键前置步骤，max_turns=10 是自然终止条件。
    必须等编译完成才能继续做题，否则编译机制就没有意义了。

    Args:
        work_dir: challenge 工作目录
        log_file_path: 原始系统日志路径，供模型按需 grep

    Returns:
        compact_handoff.md 的 Path（成功），否则 None
    """
    log_system_event(
        "[ProgressCompiler] 启动（compact 边界）",
        {"work_dir": str(work_dir), "log_file": log_file_path or "none"},
    )
    try:
        compiler = ProgressCompiler()
        return await compiler.compile(work_dir, log_file_path=log_file_path)
    except Exception as e:
        log_system_event(
            f"[ProgressCompiler] 异常: {e}",
            level=logging.WARNING,
        )
        return None
