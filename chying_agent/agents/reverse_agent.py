"""
Reverse Agent - 逆向工程专家
=============================================================

Prompt loaded from prompts/reverse.md.
"""

from ..prompts import load_prompt

REVERSE_AGENT_SYSTEM_PROMPT = load_prompt("reverse.md")

__all__ = [
    "REVERSE_AGENT_SYSTEM_PROMPT",
]
