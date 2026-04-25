"""
SQLAlchemy models for CHYing Agent database.

Tables:
- challenges: Challenge/target information
- executions: Execution attempts (with transcript_path)
- discoveries: Discovered vulnerabilities and findings
- writeups: Auto-generated writeups for solved challenges

Note:
- AgentStep, AttackEvidence 已删除：所有执行细节都在 transcript.jsonl
- session_id, langfuse_trace_id 已删除：用 transcript_path 替代
"""

from datetime import datetime, timezone, timedelta
from enum import Enum as PyEnum
from typing import List, Optional

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Index,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


# 北京时间 (UTC+8)
BEIJING_TZ = timezone(timedelta(hours=8))


def beijing_now() -> datetime:
    """获取当前北京时间"""
    return datetime.now(BEIJING_TZ).replace(tzinfo=None)


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class ExecutionStatus(str, PyEnum):
    """Status of an execution attempt."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class Challenge(Base):
    """Challenge/Target information."""
    __tablename__ = "challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    challenge_code: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    target_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    target_ip: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    target_ports: Mapped[Optional[List]] = mapped_column(JSON, nullable=True)
    difficulty: Mapped[str] = mapped_column(String(50), default="unknown")
    points: Mapped[int] = mapped_column(Integer, default=0)
    hint_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mode: Mapped[str] = mapped_column(String(50), default="ctf")  # ctf, ctf-web, pentest
    created_at: Mapped[datetime] = mapped_column(DateTime, default=beijing_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=beijing_now, onupdate=beijing_now
    )

    # Relationships
    executions: Mapped[List["Execution"]] = relationship(
        "Execution", back_populates="challenge", cascade="all, delete-orphan"
    )
    writeup: Mapped[Optional["Writeup"]] = relationship(
        "Writeup", back_populates="challenge", uselist=False
    )

    def __repr__(self) -> str:
        return f"<Challenge(code={self.challenge_code}, mode={self.mode})>"


class Execution(Base):
    """Single execution attempt of a challenge.

    Note:
    - transcript_path 替代了原有的 session_id，指向 Claude CLI 生成的 transcript.jsonl
    - 所有执行细节都在 transcript 中，DB 只存元数据
    """
    __tablename__ = "executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    challenge_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("challenges.id"), index=True
    )
    attempt_number: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[ExecutionStatus] = mapped_column(
        Enum(ExecutionStatus), default=ExecutionStatus.PENDING
    )
    flag: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    transcript_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=beijing_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    elapsed_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    total_cost_usd: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    input_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Relationships
    challenge: Mapped["Challenge"] = relationship("Challenge", back_populates="executions")
    discoveries: Mapped[List["Discovery"]] = relationship(
        "Discovery", back_populates="execution", cascade="all, delete-orphan"
    )

    # Indexes
    __table_args__ = (
        Index("ix_executions_status", "status"),
        Index("ix_executions_started_at", "started_at"),
    )

    def __repr__(self) -> str:
        return f"<Execution(id={self.id}, challenge_id={self.challenge_id}, status={self.status})>"


class Discovery(Base):
    """Discovered vulnerabilities, findings, or key information.

    由 MCP tool (upsert_memory_item) 写入，用于记录关键发现。
    """
    __tablename__ = "discoveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    execution_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("executions.id"), index=True
    )
    discovery_type: Mapped[str] = mapped_column(String(50))  # vulnerability, endpoint, credential, flag, info
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # critical, high, medium, low, info
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # NOTE: DB column name is `metadata`, but ORM attribute can't be `metadata` (SQLAlchemy reserved).
    meta: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=beijing_now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, default=beijing_now, onupdate=beijing_now, nullable=True
    )

    # Relationships
    execution: Mapped["Execution"] = relationship("Execution", back_populates="discoveries")

    # Indexes
    __table_args__ = (
        Index(
            "ux_discoveries_execution_type_title",
            "execution_id",
            "discovery_type",
            "title",
            unique=True,
        ),
    )

    def __repr__(self) -> str:
        return f"<Discovery(id={self.id}, type={self.discovery_type}, title={self.title})>"


class Writeup(Base):
    """Auto-generated writeup for solved challenges."""
    __tablename__ = "writeups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    challenge_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("challenges.id"), unique=True
    )
    content_markdown: Mapped[str] = mapped_column(Text)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=beijing_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=beijing_now, onupdate=beijing_now
    )

    # Relationships
    challenge: Mapped["Challenge"] = relationship("Challenge", back_populates="writeup")

    def __repr__(self) -> str:
        return f"<Writeup(id={self.id}, challenge_id={self.challenge_id})>"
