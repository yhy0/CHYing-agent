"""
Event Recorder (Simplified)
===========================

简化的事件记录器，配合 ExecutionContext 使用。

核心方法：
- ensure_challenge_exists: 确保题目记录存在
- start_execution: 开始执行，设置上下文
- end_execution: 结束执行，清理上下文
- upsert_memory_item: 记录关键发现（MCP tool 调用）
"""

import logging
from typing import Any, Dict, List, Optional, Sequence

from chying_agent.runtime.context import (
    get_current_execution_id,
    set_current_execution_id,
)
from .models import (
    Challenge,
    Discovery,
    Execution,
    ExecutionStatus,
    Writeup,
    beijing_now,
)
from .session import get_db

logger = logging.getLogger(__name__)


class EventRecorder:
    """简化的事件记录器

    所有方法都是 fail-safe：异常会被记录但不会传播。
    这确保记录问题永远不会影响 Agent 执行。
    """

    @staticmethod
    def ensure_challenge_exists(challenge: Dict[str, Any]) -> int:
        """确保题目记录存在，返回 challenge_id

        Args:
            challenge: 题目字典，包含 challenge_code, target_info 等

        Returns:
            Challenge database ID, or -1 on error
        """
        try:
            with get_db() as db:
                challenge_code = challenge.get(
                    "challenge_code", challenge.get("code", "unknown")
                )

                # 检查题目是否存在
                existing = (
                    db.query(Challenge)
                    .filter_by(challenge_code=challenge_code)
                    .first()
                )
                if existing:
                    # 更新现有题目信息
                    target_info = challenge.get("target_info", {})
                    if target_info:
                        existing.target_ip = target_info.get("ip")
                        existing.target_ports = target_info.get("port", [])
                    if challenge.get("_target_url"):
                        existing.target_url = challenge.get("_target_url")
                    if challenge.get("hint_content"):
                        existing.hint_content = challenge.get("hint_content")
                    existing.updated_at = beijing_now()
                    return existing.id

                # 创建新题目
                target_info = challenge.get("target_info", {})
                db_challenge = Challenge(
                    challenge_code=challenge_code,
                    target_url=challenge.get("_target_url"),
                    target_ip=target_info.get("ip"),
                    target_ports=target_info.get("port", []),
                    difficulty=challenge.get("difficulty", "unknown"),
                    points=challenge.get("points", 0),
                    hint_content=challenge.get("hint_content"),
                    mode=challenge.get("_mode", "ctf"),
                )
                db.add(db_challenge)
                db.flush()
                return db_challenge.id

        except Exception as e:
            logger.warning(f"Failed to ensure challenge exists: {e}")
            return -1

    @staticmethod
    def start_execution(challenge_id: int, attempt_number: int) -> int:
        """开始执行，返回 execution_id 并设置上下文

        Args:
            challenge_id: 题目 DB ID
            attempt_number: 尝试次数（1-based）

        Returns:
            Execution database ID, or -1 on error
        """
        if challenge_id < 0:
            return -1

        try:
            with get_db() as db:
                execution = Execution(
                    challenge_id=challenge_id,
                    attempt_number=attempt_number,
                    status=ExecutionStatus.RUNNING,
                )
                db.add(execution)
                db.flush()
                execution_id = execution.id

                # 设置上下文
                set_current_execution_id(execution_id)

                return execution_id

        except Exception as e:
            logger.warning(f"Failed to start execution: {e}")
            return -1

    @staticmethod
    def end_execution(
        success: bool,
        flag: Optional[str],
        error: Optional[str],
        transcript_path: Optional[str],
        score: int = 0,
        total_cost_usd: Optional[float] = None,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
    ) -> None:
        """结束执行（使用上下文中的 execution_id）

        Args:
            success: 是否成功
            flag: 找到的 flag（如有）
            error: 错误信息（如有）
            transcript_path: transcript 文件路径
            score: 得分
            total_cost_usd: 总消耗（美元）
            input_tokens: 输入 token 数
            output_tokens: 输出 token 数
        """
        execution_id = get_current_execution_id()
        if not execution_id or execution_id < 0:
            return

        try:
            with get_db() as db:
                execution = db.query(Execution).get(execution_id)
                if execution:
                    # 根据结果设置状态
                    if success:
                        execution.status = ExecutionStatus.SUCCESS
                    elif error == "timeout":
                        execution.status = ExecutionStatus.TIMEOUT
                    elif error == "cancelled":
                        execution.status = ExecutionStatus.CANCELLED
                    else:
                        execution.status = ExecutionStatus.FAILED

                    execution.flag = flag
                    execution.finished_at = beijing_now()
                    if execution.started_at:
                        execution.elapsed_seconds = (
                            execution.finished_at - execution.started_at
                        ).total_seconds()
                    execution.error_message = error
                    execution.score = score
                    execution.transcript_path = transcript_path
                    execution.total_cost_usd = total_cost_usd
                    execution.input_tokens = input_tokens
                    execution.output_tokens = output_tokens

                    # 如果找到 flag，记录为 discovery
                    if flag:
                        discovery = Discovery(
                            execution_id=execution_id,
                            discovery_type="flag",
                            title="FLAG Found",
                            description=f"Successfully captured flag: {flag}",
                            severity="critical",
                        )
                        db.add(discovery)

        except Exception as e:
            logger.warning(f"Failed to end execution: {e}")
        finally:
            # 清除上下文
            set_current_execution_id(None)

    @staticmethod
    def upsert_memory_item(
        kind: str,
        title: str,
        details: str = "",
        meta: Optional[Dict[str, Any]] = None,
        severity: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> Optional[int]:
        """Upsert a memory item into `discoveries`.

        De-dup key: (execution_id, kind, title).

        Args:
            kind: 发现类型 (vulnerability, endpoint, credential, flag, info)
            title: 标题
            details: 详细描述
            meta: 元数据字典
            severity: 严重程度 (critical, high, medium, low, info)
            evidence: 证据

        Returns:
            Discovery database ID, or None on error
        """
        execution_id = get_current_execution_id()
        if not execution_id or execution_id < 0:
            return None

        kind = (kind or "note").strip()
        title = (title or "Unknown").strip()
        details = (details or "").strip()

        try:
            with get_db() as db:
                existing = (
                    db.query(Discovery)
                    .filter_by(execution_id=execution_id, discovery_type=kind, title=title)
                    .first()
                )

                if existing:
                    existing.description = details
                    existing.severity = severity
                    existing.evidence = evidence
                    existing.meta = meta
                    existing.updated_at = beijing_now()
                    db.flush()
                    return existing.id

                discovery = Discovery(
                    execution_id=execution_id,
                    discovery_type=kind,
                    title=title,
                    description=details,
                    severity=severity,
                    evidence=evidence,
                    meta=meta,
                    created_at=beijing_now(),
                    updated_at=beijing_now(),
                )
                db.add(discovery)
                db.flush()
                return discovery.id

        except Exception as e:
            logger.warning(f"Failed to upsert memory item: {e}")
            return None

    @staticmethod
    def list_recent_findings(
        limit: int = 15,
        kinds: Optional[Sequence[str]] = None,
    ) -> List[Discovery]:
        """List recent memory items for the current execution.

        Args:
            limit: 最大返回数量
            kinds: 过滤的发现类型列表

        Returns:
            Discovery 列表
        """
        execution_id = get_current_execution_id()
        if not execution_id or execution_id < 0:
            return []

        try:
            with get_db() as db:
                q = db.query(Discovery).filter_by(execution_id=execution_id)
                if kinds:
                    q = q.filter(Discovery.discovery_type.in_(list(kinds)))

                # 优先按 updated_at 排序，回退到 created_at
                q = q.order_by(Discovery.updated_at.desc(), Discovery.created_at.desc())
                items = q.limit(max(int(limit), 0)).all()

                # Detach 实例，确保 session 关闭后可以安全读取属性
                for item in items:
                    db.expunge(item)
                return items

        except Exception as e:
            logger.warning(f"Failed to list memory items: {e}")
            return []

    @staticmethod
    def record_writeup(challenge_id: int, content_markdown: str) -> Optional[int]:
        """Record or update writeup for a challenge.

        Args:
            challenge_id: 题目 DB ID
            content_markdown: Markdown 格式的 writeup 内容

        Returns:
            Writeup database ID, or None on error
        """
        if challenge_id < 0:
            return None

        try:
            with get_db() as db:
                # 检查 writeup 是否存在
                existing = (
                    db.query(Writeup).filter_by(challenge_id=challenge_id).first()
                )
                if existing:
                    existing.content_markdown = content_markdown
                    existing.updated_at = beijing_now()
                    return existing.id

                writeup = Writeup(
                    challenge_id=challenge_id,
                    content_markdown=content_markdown,
                )
                db.add(writeup)
                db.flush()
                return writeup.id

        except Exception as e:
            logger.warning(f"Failed to record writeup: {e}")
            return None


# Singleton instance for easy import
recorder = EventRecorder()
