"""
Executor Agent - 安全执行专家（合并 Docker + PoC）
================================================

Prompt loaded from prompts/executor.md.
"""

from ..prompts import load_prompt

EXECUTOR_AGENT_SYSTEM_PROMPT = load_prompt("executor.md")

__all__ = [
    "EXECUTOR_AGENT_SYSTEM_PROMPT",
]
