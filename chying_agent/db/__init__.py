"""
Database layer for CHYing Agent frontend.

This module provides SQLite-based persistence for agent execution data,
enabling the frontend to display solving processes, thinking, and results.

Note:
- AgentStep, AttackEvidence 已删除：所有执行细节都在 transcript.jsonl
- 新增 ExecutionContext：异步上下文管理器，自动管理 DB 记录
"""

from .models import (
    Base,
    Challenge,
    Execution,
    Discovery,
    Writeup,
    ExecutionStatus,
)
from .session import init_db, get_db, get_db_session, get_db_dependency
from .recorder import recorder
from .execution_context import ExecutionContext

__all__ = [
    # Models
    "Base",
    "Challenge",
    "Execution",
    "Discovery",
    "Writeup",
    "ExecutionStatus",
    # Session
    "init_db",
    "get_db",
    "get_db_session",
    "get_db_dependency",
    # Recorder
    "recorder",
    # Execution Context
    "ExecutionContext",
]
