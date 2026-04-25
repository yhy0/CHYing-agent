"""
任务统计模块
============

记录解题结果统计（成功/失败计数）。
"""
import asyncio
from typing import Dict, Set


class ChallengeStats:
    """题目统计管理器"""

    def __init__(self):
        self.completed: Set[str] = set()
        self.failed: Dict[str, int] = {}  # challenge_code -> 失败次数
        self._lock = asyncio.Lock()

    async def record_success(self, challenge_code: str) -> None:
        """记录成功"""
        async with self._lock:
            self.completed.add(challenge_code)
            self.failed.pop(challenge_code, None)

    async def record_failure(self, challenge_code: str) -> None:
        """记录失败"""
        async with self._lock:
            self.failed[challenge_code] = self.failed.get(challenge_code, 0) + 1

    async def get_stats(self) -> Dict:
        """获取统计数据"""
        async with self._lock:
            return {
                "completed_count": len(self.completed),
                "failed_count": len(self.failed),
                "completed": list(self.completed),
                "failed": dict(self.failed),
            }

    async def is_completed(self, challenge_code: str) -> bool:
        """检查是否已完成"""
        async with self._lock:
            return challenge_code in self.completed

    async def get_failure_count(self, challenge_code: str) -> int:
        """获取失败次数"""
        async with self._lock:
            return self.failed.get(challenge_code, 0)
