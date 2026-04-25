"""\
Prompt Compiler Meta
====================

Loads the PromptCompiler Agent system prompt from .md file.
"""

from ..prompts import load_prompt

COMPILER_SYSTEM_PROMPT = load_prompt("prompt_compiler.md")

__all__ = ["COMPILER_SYSTEM_PROMPT"]
