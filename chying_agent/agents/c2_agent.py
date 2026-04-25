"""
C2 Agent - 后渗透操作专家
==============================

Prompt loaded from prompts/c2.md.
"""

from ..prompts import load_prompt

C2_AGENT_SYSTEM_PROMPT = load_prompt("c2.md")

__all__ = [
    "C2_AGENT_SYSTEM_PROMPT",
]
