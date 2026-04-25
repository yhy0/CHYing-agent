"""Pydantic response models for the Web Dashboard API."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ChallengeResponse(BaseModel):
    id: int
    challenge_code: str
    target_url: str | None
    target_ip: str | None
    target_ports: list | None
    difficulty: str
    points: int
    hint_content: str | None
    mode: str
    created_at: datetime
    execution_count: int
    latest_status: str | None
    flag: str | None


class ExecutionResponse(BaseModel):
    id: int
    challenge_id: int
    attempt_number: int
    status: str
    flag: str | None
    score: int
    transcript_path: str | None
    error_message: str | None
    started_at: datetime
    finished_at: datetime | None
    elapsed_seconds: float | None
    total_cost_usd: float | None
    input_tokens: int | None
    output_tokens: int | None
    has_transcript: bool


class DiscoveryResponse(BaseModel):
    id: int
    execution_id: int
    discovery_type: str
    title: str
    description: str | None
    severity: str | None
    evidence: str | None
    meta: dict | None
    created_at: datetime


# ─── Session / Transcript models (backed by SessionParser) ───


class SessionStep(BaseModel):
    """A single step from SessionParser output."""
    type: str  # user_message / thinking / tool_call / tool_result / summary
    timestamp: str | None = None
    content: str | None = None
    # tool_call specific
    tool: str | None = None
    tool_use_id: str | None = None
    input: Any | None = None
    # tool_result specific
    output: Any | None = None
    success: bool | None = None


class SessionSummary(BaseModel):
    """Statistics from SessionParser."""
    total_steps: int
    user_messages: int
    thinking_count: int
    tool_calls: int
    tool_results: int
    duration_seconds: float | None
    tool_breakdown: dict[str, int] = {}


class SessionMeta(BaseModel):
    """Metadata from SessionParser."""
    file_path: str | None = None
    session_id: str | None = None
    agent_id: str | None = None
    model: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    is_subagent: bool = False


class SubagentInfo(BaseModel):
    """Subagent session info."""
    agent_id: str | None = None
    summary: SessionSummary
    metadata: SessionMeta
    steps: list[SessionStep]


class TranscriptResponse(BaseModel):
    """Full parsed transcript response."""
    success: bool
    error: str | None = None
    steps: list[SessionStep]
    summary: SessionSummary | None = None
    metadata: SessionMeta | None = None
    subagents: list[SubagentInfo] = []
    # Pagination info (applied to steps)
    total_steps: int = 0
    page: int = 1
    page_size: int = 50
    total_pages: int = 1


class LogEntry(BaseModel):
    """A single parsed entry from a .log file."""
    timestamp: str
    level: str
    source: str                    # SYSTEM / TOOL / USER / RAW
    agent: str | None              # Orchestrator / Subagent:executor / PromptCompiler / …
    event_type: str                # thinking / tool_call / tool_result / recon / header / …
    event_text: str
    kv: dict[str, Any] = {}


class LogResponse(BaseModel):
    """Full parsed log response."""
    success: bool
    error: str | None = None
    total: int = 0
    entries: list[LogEntry] = []
    # Pagination
    page: int = 1
    page_size: int = 200
    total_pages: int = 1


class WriteupResponse(BaseModel):
    id: int
    challenge_id: int
    content_markdown: str
    generated_at: datetime
    updated_at: datetime


class DashboardStats(BaseModel):
    total_challenges: int
    success_count: int
    failed_count: int
    running_count: int
    pending_count: int
    total_discoveries: int
    total_writeups: int
    total_cost_usd: float
    total_input_tokens: int
    total_output_tokens: int
    recent_executions: list[ExecutionResponse]


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    total_pages: int
