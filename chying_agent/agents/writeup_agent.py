"""
Writeup Agent - 安全研究报告撰写专家系统提示词
===============================================

Prompt loaded from prompts/writeup.md.
"""

from ..prompts import load_prompt

WRITEUP_AGENT_SYSTEM_PROMPT = load_prompt("writeup.md")
