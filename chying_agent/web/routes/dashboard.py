"""Dashboard statistics API."""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from chying_agent.db.models import Challenge, Execution, Discovery, Writeup, ExecutionStatus
from chying_agent.db.session import get_db_dependency
from chying_agent.web.schemas import DashboardStats
from chying_agent.web.routes.executions import _execution_to_response

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db_dependency)):
    """Get dashboard statistics overview."""
    total_challenges = db.query(func.count(Challenge.id)).scalar() or 0
    total_discoveries = db.query(func.count(Discovery.id)).scalar() or 0
    total_writeups = db.query(func.count(Writeup.id)).scalar() or 0

    # Cost / token totals
    total_cost_usd = db.query(func.coalesce(func.sum(Execution.total_cost_usd), 0.0)).scalar()
    total_input_tokens = db.query(func.coalesce(func.sum(Execution.input_tokens), 0)).scalar()
    total_output_tokens = db.query(func.coalesce(func.sum(Execution.output_tokens), 0)).scalar()

    # Count challenges by their latest execution status
    success_count = 0
    failed_count = 0
    running_count = 0
    pending_count = 0

    challenges = db.query(Challenge).all()
    for ch in challenges:
        if not ch.executions:
            pending_count += 1
            continue
        latest = max(ch.executions, key=lambda e: e.started_at)
        status = latest.status.value if isinstance(latest.status, ExecutionStatus) else str(latest.status)
        if status == ExecutionStatus.SUCCESS.value:
            success_count += 1
        elif status == ExecutionStatus.RUNNING.value:
            running_count += 1
        elif status in (ExecutionStatus.FAILED.value, ExecutionStatus.TIMEOUT.value, ExecutionStatus.CANCELLED.value):
            failed_count += 1
        else:
            pending_count += 1

    # Recent executions
    recent_execs = (
        db.query(Execution)
        .order_by(Execution.started_at.desc())
        .limit(10)
        .all()
    )

    return DashboardStats(
        total_challenges=total_challenges,
        success_count=success_count,
        failed_count=failed_count,
        running_count=running_count,
        pending_count=pending_count,
        total_discoveries=total_discoveries,
        total_writeups=total_writeups,
        total_cost_usd=total_cost_usd,
        total_input_tokens=total_input_tokens,
        total_output_tokens=total_output_tokens,
        recent_executions=[_execution_to_response(ex) for ex in recent_execs],
    )
