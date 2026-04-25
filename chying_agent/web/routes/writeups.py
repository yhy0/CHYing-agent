"""Writeups API routes."""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from chying_agent.db.models import Challenge, ExecutionStatus
from chying_agent.db.session import get_db_dependency
from chying_agent.web.schemas import WriteupResponse
from chying_agent.writeup_generator import generate_writeup

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/{challenge_id}", response_model=WriteupResponse | None)
def get_writeup(challenge_id: int, db: Session = Depends(get_db_dependency)):
    """Get writeup for a challenge."""
    ch = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not ch:
        raise HTTPException(status_code=404, detail="Challenge not found")

    if not ch.writeup:
        return None

    return WriteupResponse(
        id=ch.writeup.id,
        challenge_id=ch.writeup.challenge_id,
        content_markdown=ch.writeup.content_markdown,
        generated_at=ch.writeup.generated_at,
        updated_at=ch.writeup.updated_at,
    )


@router.post("/{challenge_id}/generate")
async def generate_writeup_api(challenge_id: int, db: Session = Depends(get_db_dependency)):
    """Generate a writeup for a challenge using the WriteupAgent."""
    ch = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not ch:
        raise HTTPException(status_code=404, detail="Challenge not found")

    if not ch.executions:
        raise HTTPException(status_code=400, detail="No executions found for this challenge")

    # 从 DB 构建 challenge_info 和 work_dir
    challenge_info = {
        "challenge_code": ch.challenge_code,
        "mode": ch.mode,
        "difficulty": ch.difficulty,
        "points": ch.points,
    }
    if ch.target_url:
        challenge_info["target_url"] = ch.target_url
    if ch.target_ip:
        challenge_info["target_ip"] = ch.target_ip
    if ch.hint_content:
        challenge_info["hint_content"] = ch.hint_content

    # 找最佳执行记录获取 flag 和 work_dir
    executions = sorted(ch.executions, key=lambda e: e.started_at, reverse=True)
    best_exec = None
    for ex in executions:
        status = ex.status.value if isinstance(ex.status, ExecutionStatus) else str(ex.status)
        if status == ExecutionStatus.SUCCESS.value:
            best_exec = ex
            break
    if not best_exec and executions:
        best_exec = executions[0]

    if best_exec and best_exec.flag:
        challenge_info["flag"] = best_exec.flag

    # 确定 work_dir：从 transcript 路径推断，或用默认路径
    work_dir = None
    if best_exec and best_exec.transcript_path:
        tp = Path(best_exec.transcript_path)
        if tp.exists():
            work_dir = tp.parent
    if work_dir is None:
        from chying_agent.utils.path_utils import get_host_agent_work_dir
        category = (ch.mode or "web").capitalize()
        work_dir = get_host_agent_work_dir() / "ctf" / category.capitalize() / ch.challenge_code

    try:
        content = await generate_writeup(work_dir, challenge_info, challenge_db_id=ch.id)

        if not content:
            raise HTTPException(status_code=500, detail="Writeup generation returned empty content")

        # Re-fetch from DB (generate_writeup 已保存)
        db.refresh(ch)
        if not ch.writeup:
            raise HTTPException(status_code=500, detail="Failed to retrieve saved writeup")

        return WriteupResponse(
            id=ch.writeup.id,
            challenge_id=ch.writeup.challenge_id,
            content_markdown=ch.writeup.content_markdown,
            generated_at=ch.writeup.generated_at,
            updated_at=ch.writeup.updated_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Writeup generation failed")
        raise HTTPException(status_code=500, detail=f"Writeup generation failed: {e}")
