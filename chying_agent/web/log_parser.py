"""Log file parser for CHYing Agent execution logs.

Parses structured `.log` files from `logs/challenges/` into timeline entries
with agent attribution, event type, timestamp, and content.

Log line format:
    {timestamp} [{level}] | [{source}] [{agent}] {event} | {kv_pairs}

Examples:
    2026-04-14 14:38:05 [INFO] | [SYSTEM] [PromptCompiler] 💭 思考过程 | thinking="..."
    2026-04-14 14:39:02 [INFO] | [TOOL] 🔧 [Orchestrator] 调用工具: Agent:executor | id=... input={...}
    2026-04-14 14:39:12 [INFO] | [TOOL] ✅ [Subagent:executor] 工具完成: mcp__chying__exec | ...
    2026-04-14 14:38:45 [INFO] | [SYSTEM] [PromptCompiler] Token Usage: ... | Cost: ...

Header lines (no | separator after level):
    2026-04-14 14:36:42 [INFO] |
    ================================================================================
    🎯 题目: xxx - 首次尝试（2026-04-14 14:36:42）
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Regex patterns ────────────────────────────────────────────────────────────

# Full structured line: timestamp [LEVEL] | [SOURCE] [AGENT] event_text | kv_data
_RE_FULL = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"  # 1: timestamp
    r"\s+\[(\w+)\]"                               # 2: level
    r"\s+\|\s+"                                   # pipe separator
    r"\[(\w+)\]"                                  # 3: source  (SYSTEM / TOOL / USER)
    r"\s+"
    r"(?:\[([^\]]+)\]\s+)?"                        # 4: agent   (optional)
    r"(.+?)$"                                      # 5: rest of line
)

# Bare-pipe line: timestamp [LEVEL] |
_RE_PIPE_ONLY = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+\|\s*$"
)

# Split event text from kv suffix: "event text | key=val ..."
_RE_KV_SPLIT = re.compile(r"\s+\|\s+(.+)$")


# ── Event-type detection ──────────────────────────────────────────────────────

def _classify_event(source: str, agent: Optional[str], event_text: str) -> str:
    """Infer a canonical event-type string from the parsed fields."""
    text = event_text.lower()

    # TOOL source
    if source == "TOOL":
        if "调用工具" in event_text or "🔧" in event_text:
            return "tool_call"
        if "工具完成" in event_text or "✅" in event_text:
            return "tool_result"
        if "工具失败" in event_text or "❌" in event_text:
            return "tool_error"
        return "tool_event"

    # SYSTEM source — agent-specific
    if agent:
        ag = agent.lower()
        if "promptcompiler" in ag or "prompt" in ag:
            if "token usage" in text or "cost" in text:
                return "token_usage"
            if "思考过程" in event_text or "💭" in event_text:
                return "thinking"
            if "文本响应" in event_text or "📝" in event_text:
                return "text_response"
            if "编译" in text or "compile" in text:
                return "compile"
            if "init" in text or "系统消息" in text:
                return "system_init"
            return "prompt_event"
        if "orchestrator" in ag or "agent" == ag:
            if "系统消息" in event_text:
                return "system_message"
            if "使用专业化" in event_text or "full_prompt" in event_text:
                return "prompt_ready"
            return "orchestrator_event"
        if "自动侦察" in agent or "recon" in ag:
            return "recon"
        if "解题" in agent:
            return "challenge_start"
        if "executor" in ag:
            if "执行完成" in text:
                return "exec_done"
            return "exec_event"
        if "mcp" in ag or "httpx" in ag or "web工具" in agent:
            return "mcp_event"

    # Fallback
    if "executor" in text and "执行完成" in text:
        return "exec_done"
    return "system_event"


# ── KV parser ─────────────────────────────────────────────────────────────────

def _parse_kv(kv_str: str) -> Dict[str, Any]:
    """Best-effort key=value parser (handles JSON values and quoted strings)."""
    result: Dict[str, Any] = {}
    if not kv_str:
        return result

    # Split on top-level `key=` boundaries, handling nested JSON/quotes
    # Use a simple state machine
    parts: List[str] = []
    depth = 0
    buf = []
    in_string = False
    escape = False

    for ch in kv_str:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            buf.append(ch)
            continue
        if in_string:
            buf.append(ch)
            continue
        if ch in ("{", "[", "("):
            depth += 1
            buf.append(ch)
        elif ch in ("}", "]", ")"):
            depth -= 1
            buf.append(ch)
        elif ch == " " and depth == 0:
            tok = "".join(buf).strip()
            if tok:
                parts.append(tok)
            buf = []
        else:
            buf.append(ch)

    if buf:
        tok = "".join(buf).strip()
        if tok:
            parts.append(tok)

    for part in parts:
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.strip()
            v = v.strip()
            # Try to strip outer quotes
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            result[k] = v
        else:
            # bare value — add as a numbered entry
            result[f"_extra_{len(result)}"] = part

    return result


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    """A single parsed log entry."""
    timestamp: str
    level: str
    source: str                          # SYSTEM / TOOL / USER / RAW
    agent: Optional[str]                 # Orchestrator / Subagent:executor / PromptCompiler / …
    event_type: str                      # thinking / tool_call / tool_result / …
    event_text: str                      # The human-readable part of the message
    kv: Dict[str, Any] = field(default_factory=dict)
    raw_line: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "source": self.source,
            "agent": self.agent,
            "event_type": self.event_type,
            "event_text": self.event_text,
            "kv": self.kv,
        }


# ── Parser ────────────────────────────────────────────────────────────────────

class LogParser:
    """Parse a CHYing Agent .log file into a list of LogEntry objects."""

    def __init__(self, log_path: str) -> None:
        self.log_path = Path(log_path)

    def parse(self) -> List[LogEntry]:
        entries: List[LogEntry] = []

        if not self.log_path.exists():
            return entries

        with self.log_path.open(encoding="utf-8", errors="replace") as fh:
            pending_timestamp: Optional[str] = None
            pending_level: Optional[str] = None

            for raw_line in fh:
                line = raw_line.rstrip("\n")
                if not line.strip():
                    continue

                # Try to match a bare-pipe line (header divider)
                m_pipe = _RE_PIPE_ONLY.match(line)
                if m_pipe:
                    pending_timestamp = m_pipe.group(1)
                    pending_level = m_pipe.group(2)
                    continue

                # Try to match a full structured line
                m = _RE_FULL.match(line)
                if m:
                    timestamp = m.group(1)
                    level = m.group(2)
                    source = m.group(3)
                    agent = m.group(4)
                    rest = m.group(5).strip()

                    # Split event_text from kv suffix
                    kv_match = _RE_KV_SPLIT.search(rest)
                    if kv_match:
                        event_text = rest[: kv_match.start()].strip()
                        kv = _parse_kv(kv_match.group(1))
                    else:
                        event_text = rest
                        kv = {}

                    event_type = _classify_event(source, agent, event_text)

                    entries.append(LogEntry(
                        timestamp=timestamp,
                        level=level,
                        source=source,
                        agent=agent,
                        event_type=event_type,
                        event_text=event_text,
                        kv=kv,
                        raw_line=line,
                    ))
                    pending_timestamp = None
                    pending_level = None
                    continue

                # Non-matching line after a bare-pipe: treat as RAW header text
                if pending_timestamp:
                    text = line.strip()
                    if text:
                        # Skip pure divider lines (===== / -----)
                        if re.match(r"^[=\-*#+\s]+$", text):
                            continue
                        entries.append(LogEntry(
                            timestamp=pending_timestamp,
                            level=pending_level or "INFO",
                            source="RAW",
                            agent=None,
                            event_type="header",
                            event_text=text,
                            raw_line=line,
                        ))
                # else: unrecognised line, skip silently

        return entries

    def parse_dict(self) -> Dict[str, Any]:
        """Return parse result as a serialisable dict."""
        entries = self.parse()
        return {
            "success": True,
            "total": len(entries),
            "entries": [e.to_dict() for e in entries],
        }
