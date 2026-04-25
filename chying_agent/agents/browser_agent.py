"""
Browser Agent - 浏览器操作专家
==============================

Prompt loaded from prompts/browser.md.
"""

from ..prompts import load_prompt

BROWSER_AGENT_SYSTEM_PROMPT = load_prompt("browser.md")

__all__ = [
    "BROWSER_AGENT_SYSTEM_PROMPT",
]
