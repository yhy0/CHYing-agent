"""Prompt loader: read .md files from this directory.

All prompts are stored as Markdown files in this package directory.
Python modules import ``load_prompt("filename.md")`` to get the raw text.
"""

from __future__ import annotations

from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


def load_prompt(name: str) -> str:
    """Load a prompt file by name from the prompts directory.

    Args:
        name: Filename with ``.md`` extension, e.g. ``"executor.md"``.

    Returns:
        The full text content of the prompt file.

    Raises:
        FileNotFoundError: If the prompt file does not exist.
    """
    path = _PROMPTS_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Prompt file not found: {path}")
    return path.read_text(encoding="utf-8")


__all__ = ["load_prompt"]
