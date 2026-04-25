"""\
Orchestrator System Prompt
==========================

Loads prompt sections from .md files and assembles the orchestrator system prompt.
"""

from __future__ import annotations

from ..prompts import load_prompt


def get_brain_prompt() -> str:
    """Build the Orchestrator system prompt from .md files.

    Loads 4 sections: identity, strategy, constraints, output_schema.
    Returns an XML-wrapped system prompt string.
    """
    parts = [
        load_prompt("orchestrator_identity.md"),
        load_prompt("orchestrator_strategy.md"),
        load_prompt("orchestrator_constraints.md"),
        load_prompt("orchestrator_output.md"),
    ]
    content = "\n\n".join(parts)
    return f"<system_prompt>\n{content}\n</system_prompt>"


__all__ = ["get_brain_prompt"]
