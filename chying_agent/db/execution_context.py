"""
执行上下文管理器
================

使用异步上下文管理器自动管理 DB 记录的生命周期：
- __aenter__: 创建题目记录（如不存在）、创建执行记录
- __aexit__: 根据结果更新执行状态、处理异常

使用方法：
    async with ExecutionContext(challenge, attempt_number) as ctx:
        result = await orchestrator.run(context)
        ctx.set_result(result, success=True, flag="flag{...}")
"""

import asyncio
import logging
from typing import Any, Dict, Optional

from chying_agent.runtime.context import set_current_execution_id
from .recorder import recorder

logger = logging.getLogger(__name__)


class ExecutionContext:
    """异步执行上下文管理器

    自动处理：
    - 题目记录创建/更新
    - 执行记录创建
    - 执行状态更新（正常结束或异常）
    - 上下文变量设置/清理
    """

    def __init__(
        self,
        challenge: Dict[str, Any],
        attempt_number: int = 1,
    ):
        """
        Args:
            challenge: 题目字典，包含 challenge_code, target_info 等
            attempt_number: 尝试次数（1-based）
        """
        self.challenge = challenge
        self.attempt_number = attempt_number

        # DB IDs
        self._challenge_db_id: Optional[int] = None
        self._execution_id: Optional[int] = None

        # 执行结果（由 set_result 设置）
        self._result: Optional[Any] = None
        self._success: bool = False
        self._flag: Optional[str] = None
        self._error: Optional[str] = None
        self._score: int = 0
        self._transcript_path: Optional[str] = None

    async def __aenter__(self) -> "ExecutionContext":
        """进入上下文：创建 DB 记录"""
        challenge_code = self.challenge.get("challenge_code", "unknown")

        # 1. 确保题目记录存在
        self._challenge_db_id = recorder.ensure_challenge_exists(self.challenge)

        # 2. 创建执行记录
        self._execution_id = recorder.start_execution(
            self._challenge_db_id,
            self.attempt_number,
        )

        logger.debug(
            f"[ExecutionContext] 开始执行: challenge={challenge_code}, "
            f"execution_id={self._execution_id}"
        )

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        """退出上下文：更新执行状态"""
        if exc_type is not None:
            # 异常退出
            error = self._map_exception_to_error(exc_type, exc_val)
            transcript_path = self._transcript_path or getattr(self._result, "transcript_path", None)
            recorder.end_execution(
                success=False,
                flag=None,
                error=error,
                transcript_path=transcript_path,
            )
            logger.warning(f"[ExecutionContext] 执行异常: {error}")
            return False  # 不抑制异常

        # 正常退出
        if self._result is not None:
            transcript_path = self._transcript_path or getattr(self._result, "transcript_path", None)
            # 从 result 对象提取 cost/token 数据
            total_cost_usd = getattr(self._result, "total_cost_usd", None)
            usage = getattr(self._result, "usage", None) or {}
            input_tokens = usage.get("input_tokens") or None
            output_tokens = usage.get("output_tokens") or None
            recorder.end_execution(
                success=self._success,
                flag=self._flag,
                error=self._error,
                transcript_path=transcript_path,
                score=self._score,
                total_cost_usd=total_cost_usd,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
            logger.debug(
                f"[ExecutionContext] 执行结束: success={self._success}, "
                f"flag={self._flag is not None}"
            )
        else:
            # 未调用 set_result
            recorder.end_execution(
                success=False,
                flag=None,
                error="no_result",
                transcript_path=None,
            )
            logger.warning("[ExecutionContext] 退出时未设置 result")

        return False

    def set_result(
        self,
        result: Any,
        success: bool = False,
        flag: Optional[str] = None,
        error: Optional[str] = None,
        score: int = 0,
        transcript_path: Optional[str] = None,
    ) -> None:
        """设置执行结果（供 __aexit__ 使用）

        Args:
            result: Orchestrator 返回的结果对象
            success: 是否成功
            flag: 找到的 flag（如有）
            error: 错误信息（如有）
            score: 得分
            transcript_path: 显式指定的 transcript 路径（优先于 result 对象中的路径）
        """
        self._result = result
        self._success = success
        self._flag = flag
        self._error = error
        self._score = score
        self._transcript_path = transcript_path

    @staticmethod
    def _map_exception_to_error(exc_type, exc_val) -> str:
        """将异常类型映射为错误标识"""
        if exc_type is asyncio.TimeoutError:
            return "timeout"
        elif exc_type is asyncio.CancelledError:
            return "cancelled"
        elif exc_type is KeyboardInterrupt:
            return "user_interrupt"
        else:
            return f"exception: {exc_type.__name__}: {str(exc_val)}"

    @property
    def execution_id(self) -> Optional[int]:
        """获取执行 ID"""
        return self._execution_id

    @property
    def challenge_db_id(self) -> Optional[int]:
        """获取题目 DB ID"""
        return self._challenge_db_id
