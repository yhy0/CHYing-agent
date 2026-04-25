"""Executions API routes."""

import math
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from chying_agent.claude_sdk.session_parser import SessionParser
from chying_agent.db.models import Execution, ExecutionStatus
from chying_agent.db.session import get_db_dependency
from chying_agent.web.log_parser import LogParser
from chying_agent.web.schemas import (
    DiscoveryResponse,
    ExecutionResponse,
    LogEntry,
    LogResponse,
    SessionStep,
    SessionSummary,
    SessionMeta,
    SubagentInfo,
    TranscriptResponse,
)

router = APIRouter()


def _execution_to_response(ex: Execution) -> ExecutionResponse:
    has_transcript = False
    if ex.transcript_path:
        has_transcript = Path(ex.transcript_path).exists()
    return ExecutionResponse(
        id=ex.id,
        challenge_id=ex.challenge_id,
        attempt_number=ex.attempt_number,
        status=ex.status.value if isinstance(ex.status, ExecutionStatus) else str(ex.status),
        flag=ex.flag,
        score=ex.score,
        transcript_path=ex.transcript_path,
        error_message=ex.error_message,
        started_at=ex.started_at,
        finished_at=ex.finished_at,
        elapsed_seconds=ex.elapsed_seconds,
        total_cost_usd=ex.total_cost_usd,
        input_tokens=ex.input_tokens,
        output_tokens=ex.output_tokens,
        has_transcript=has_transcript,
    )


def _raw_steps_to_schema(raw_steps: list[dict]) -> list[SessionStep]:
    """Convert raw step dicts from SessionParser to Pydantic models."""
    return [SessionStep(**step) for step in raw_steps]


@router.get("/{execution_id}")
def get_execution(execution_id: int, db: Session = Depends(get_db_dependency)):
    """Get execution metadata and discoveries."""
    ex = db.query(Execution).filter(Execution.id == execution_id).first()
    if not ex:
        raise HTTPException(status_code=404, detail="Execution not found")

    discoveries = [
        DiscoveryResponse(
            id=d.id,
            execution_id=d.execution_id,
            discovery_type=d.discovery_type,
            title=d.title,
            description=d.description,
            severity=d.severity,
            evidence=d.evidence,
            meta=d.meta,
            created_at=d.created_at,
        )
        for d in ex.discoveries
    ]

    return {
        "execution": _execution_to_response(ex),
        "discoveries": discoveries,
    }


@router.get("/{execution_id}/writeup")
def get_execution_writeup(execution_id: int, db: Session = Depends(get_db_dependency)):
    """读取 execution 工作目录下的 writeup.md 原始内容。

    通过 transcript_path 的父目录推算工作目录。
    """
    ex = db.query(Execution).filter(Execution.id == execution_id).first()
    if not ex:
        raise HTTPException(status_code=404, detail="Execution not found")

    if not ex.transcript_path:
        raise HTTPException(status_code=404, detail="No transcript path, cannot locate work dir")

    work_dir = Path(ex.transcript_path).parent
    writeup_file = work_dir / "writeup.md"

    if not writeup_file.exists():
        return {"content": None}

    try:
        content = writeup_file.read_text(encoding="utf-8")
        return {"content": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read writeup: {e}")


@router.get("/{execution_id}/transcript", response_model=TranscriptResponse)
def get_execution_transcript(
    execution_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db_dependency),
):
    """Get parsed transcript for an execution using SessionParser.

    Returns structured steps with statistics, metadata, and subagent info.
    Steps are paginated; summary/metadata/subagents are always returned in full.
    """
    ex = db.query(Execution).filter(Execution.id == execution_id).first()
    if not ex:
        raise HTTPException(status_code=404, detail="Execution not found")

    if not ex.transcript_path:
        raise HTTPException(status_code=404, detail="No transcript path recorded")

    transcript_file = Path(ex.transcript_path)
    if not transcript_file.exists():
        raise HTTPException(status_code=404, detail="Transcript file not found on disk")

    # Use SessionParser for full parsing (including subagents)
    parser = SessionParser(str(transcript_file), include_subagents=True)
    result = parser.parse()

    if not result.get("success"):
        return TranscriptResponse(
            success=False,
            error=result.get("error", "Parse failed"),
            steps=[],
        )

    all_steps = _raw_steps_to_schema(result.get("steps", []))
    total = len(all_steps)
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    start = (page - 1) * page_size
    end = start + page_size
    page_steps = all_steps[start:end]

    # Build summary
    raw_summary = result.get("summary", {})
    summary = SessionSummary(
        total_steps=raw_summary.get("total_steps", total),
        user_messages=raw_summary.get("user_messages", 0),
        thinking_count=raw_summary.get("thinking_count", 0),
        tool_calls=raw_summary.get("tool_calls", 0),
        tool_results=raw_summary.get("tool_results", 0),
        duration_seconds=raw_summary.get("duration_seconds"),
        tool_breakdown=raw_summary.get("tool_breakdown", {}),
    )

    # Build metadata
    raw_meta = result.get("metadata", {})
    metadata = SessionMeta(
        file_path=raw_meta.get("file_path"),
        session_id=raw_meta.get("session_id"),
        agent_id=raw_meta.get("agent_id"),
        model=raw_meta.get("model"),
        start_time=raw_meta.get("start_time"),
        end_time=raw_meta.get("end_time"),
        is_subagent=raw_meta.get("is_subagent", False),
    )

    # Build subagents
    subagents = []
    for sa in result.get("subagents", []):
        sa_summary_raw = sa.get("summary", {})
        sa_meta_raw = sa.get("metadata", {})
        subagents.append(SubagentInfo(
            agent_id=sa.get("agent_id"),
            summary=SessionSummary(
                total_steps=sa_summary_raw.get("total_steps", 0),
                user_messages=sa_summary_raw.get("user_messages", 0),
                thinking_count=sa_summary_raw.get("thinking_count", 0),
                tool_calls=sa_summary_raw.get("tool_calls", 0),
                tool_results=sa_summary_raw.get("tool_results", 0),
                duration_seconds=sa_summary_raw.get("duration_seconds"),
                tool_breakdown=sa_summary_raw.get("tool_breakdown", {}),
            ),
            metadata=SessionMeta(
                file_path=sa_meta_raw.get("file_path"),
                session_id=sa_meta_raw.get("session_id"),
                agent_id=sa_meta_raw.get("agent_id"),
                model=sa_meta_raw.get("model"),
                start_time=sa_meta_raw.get("start_time"),
                end_time=sa_meta_raw.get("end_time"),
                is_subagent=True,
            ),
            steps=_raw_steps_to_schema(sa.get("steps", [])),
        ))

    return TranscriptResponse(
        success=True,
        steps=page_steps,
        summary=summary,
        metadata=metadata,
        subagents=subagents,
        total_steps=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{execution_id}/log", response_model=LogResponse)
def get_execution_log(
    execution_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db_dependency),
):
    """Get parsed timeline log entries for an execution.

    Reads the matching .log file from logs/challenges/ directory.
    The log file is inferred from the challenge_code + started_at timestamp
    stored in the Execution record.
    """
    ex = db.query(Execution).filter(Execution.id == execution_id).first()
    if not ex:
        raise HTTPException(status_code=404, detail="Execution not found")

    # Locate log file: derive from transcript_path's parent or project-relative logs/challenges/
    log_file = _find_log_file(ex)
    if log_file is None:
        return LogResponse(
            success=False,
            error="Log file not found",
        )

    parser = LogParser(str(log_file))
    result = parser.parse_dict()

    if not result.get("success"):
        return LogResponse(
            success=False,
            error=result.get("error", "Parse failed"),
        )

    all_entries = [LogEntry(**e) for e in result.get("entries", [])]
    total = len(all_entries)
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    start = (page - 1) * page_size
    end = start + page_size

    return LogResponse(
        success=True,
        total=total,
        entries=all_entries[start:end],
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


def _find_log_file(ex: Execution) -> Path | None:
    """Try to locate the .log file that corresponds to an Execution record.

    Strategy (in order):
    1. transcript_path parent → look for *.log files with matching name pattern
    2. Project root logs/challenges/ directory → match by challenge_code + date
    """
    from chying_agent.db.models import Challenge

    # Get challenge code from the related challenge
    challenge_code: str | None = None
    if ex.challenge_id:
        from chying_agent.db.session import get_db
        try:
            with get_db() as db:
                ch = db.query(Challenge).filter(Challenge.id == ex.challenge_id).first()
                if ch:
                    challenge_code = ch.challenge_code
        except Exception:
            pass

    started_at = ex.started_at
    if started_at is None:
        return None

    # Build expected filename stem: {challenge_code}_{YYYYMMDD}_{HHMMSS}
    date_str = started_at.strftime("%Y%m%d")
    time_str = started_at.strftime("%H%M%S")

    # Strategy 1: use transcript_path to find the logs dir
    if ex.transcript_path:
        work_dir = Path(ex.transcript_path).parent
        # Walk up to find logs/challenges/
        for parent in [work_dir] + list(work_dir.parents)[:5]:
            logs_dir = parent / "logs" / "challenges"
            if logs_dir.exists():
                candidate = _search_log_dir(logs_dir, challenge_code, date_str, time_str)
                if candidate:
                    return candidate

    # Strategy 2: well-known project-relative paths
    # __file__ is chying_agent/web/routes/executions.py → go 4 levels up to project root
    pkg_root = Path(__file__).parent.parent.parent.parent
    logs_dir = pkg_root / "logs" / "challenges"
    if logs_dir.exists() and challenge_code:
        candidate = _search_log_dir(logs_dir, challenge_code, date_str, time_str)
        if candidate:
            return candidate

    return None


def _search_log_dir(
    logs_dir: Path,
    challenge_code: str | None,
    date_str: str,
    time_str: str,
) -> Path | None:
    """Search logs_dir for a matching .log file."""
    if challenge_code:
        # Exact match first
        exact = logs_dir / f"{challenge_code}_{date_str}_{time_str}.log"
        if exact.exists():
            return exact
        # Match by challenge_code + date (ignore seconds drift)
        for f in logs_dir.glob(f"{challenge_code}_{date_str}_*.log"):
            return f  # Return first match

    # Fallback: match by date+time prefix only
    for f in logs_dir.glob(f"*_{date_str}_{time_str}.log"):
        return f

    # Fallback: match by date only (latest file that day)
    candidates = list(logs_dir.glob(f"*_{date_str}_*.log"))
    if candidates:
        return max(candidates, key=lambda p: p.stat().st_mtime)

    return None
