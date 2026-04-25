"""Challenges API routes."""

import math

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from chying_agent.db.models import Challenge, Execution, ExecutionStatus
from chying_agent.db.session import get_db_dependency
from chying_agent.web.schemas import (
    ChallengeResponse,
    DiscoveryResponse,
    WriteupResponse,
)
from chying_agent.web.routes.executions import _execution_to_response

router = APIRouter()


def _get_challenge_status(ch: Challenge) -> tuple[str | None, str | None]:
    """Return (latest_status, flag) from the most recent execution."""
    if not ch.executions:
        return None, None
    latest = max(ch.executions, key=lambda e: e.started_at)
    status = latest.status.value if isinstance(latest.status, ExecutionStatus) else str(latest.status)
    # Find flag from any successful execution
    flag = None
    for ex in ch.executions:
        if ex.flag:
            flag = ex.flag
            break
    return status, flag


def _challenge_to_response(ch: Challenge) -> ChallengeResponse:
    latest_status, flag = _get_challenge_status(ch)
    return ChallengeResponse(
        id=ch.id,
        challenge_code=ch.challenge_code,
        target_url=ch.target_url,
        target_ip=ch.target_ip,
        target_ports=ch.target_ports,
        difficulty=ch.difficulty,
        points=ch.points,
        hint_content=ch.hint_content,
        mode=ch.mode,
        created_at=ch.created_at,
        execution_count=len(ch.executions),
        latest_status=latest_status,
        flag=flag,
    )


@router.get("")
def list_challenges(
    mode: str | None = Query(None, description="Filter by mode (ctf, pentest)"),
    status: str | None = Query(None, description="Filter by latest status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db_dependency),
):
    """List all challenges with pagination and filtering."""
    query = db.query(Challenge).order_by(Challenge.created_at.desc())

    if mode:
        query = query.filter(Challenge.mode == mode)

    all_challenges = query.all()

    # Apply status filter in Python (requires relationship traversal)
    if status:
        filtered = []
        for ch in all_challenges:
            latest_status, _ = _get_challenge_status(ch)
            if latest_status == status:
                filtered.append(ch)
        all_challenges = filtered

    total = len(all_challenges)
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    start = (page - 1) * page_size
    end = start + page_size
    page_items = all_challenges[start:end]

    return {
        "items": [_challenge_to_response(ch) for ch in page_items],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@router.get("/{challenge_id}")
def get_challenge(challenge_id: int, db: Session = Depends(get_db_dependency)):
    """Get complete challenge details including executions, discoveries, and writeup."""
    ch = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not ch:
        raise HTTPException(status_code=404, detail="Challenge not found")

    challenge_resp = _challenge_to_response(ch)

    executions = sorted(ch.executions, key=lambda e: e.started_at, reverse=True)
    execution_responses = [_execution_to_response(ex) for ex in executions]

    # Collect all discoveries across executions
    discoveries = []
    for ex in executions:
        for disc in ex.discoveries:
            discoveries.append(DiscoveryResponse(
                id=disc.id,
                execution_id=disc.execution_id,
                discovery_type=disc.discovery_type,
                title=disc.title,
                description=disc.description,
                severity=disc.severity,
                evidence=disc.evidence,
                meta=disc.meta,
                created_at=disc.created_at,
            ))

    writeup = None
    if ch.writeup:
        writeup = WriteupResponse(
            id=ch.writeup.id,
            challenge_id=ch.writeup.challenge_id,
            content_markdown=ch.writeup.content_markdown,
            generated_at=ch.writeup.generated_at,
            updated_at=ch.writeup.updated_at,
        )

    return {
        "challenge": challenge_resp,
        "executions": execution_responses,
        "discoveries": discoveries,
        "writeup": writeup,
    }
