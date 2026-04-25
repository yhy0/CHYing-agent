"""CTF 平台 Flag 提交 Agent 系统提示词。

Prompt loaded from prompts/flag_submitter.md.
"""

from ..prompts import load_prompt

FLAG_SUBMITTER_AGENT_SYSTEM_PROMPT = load_prompt("flag_submitter.md")

__all__ = ["FLAG_SUBMITTER_AGENT_SYSTEM_PROMPT"]
