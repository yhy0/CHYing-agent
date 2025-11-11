"""
任务管理器模块
==============

负责管理并发解题任务的生命周期：
- 任务创建、跟踪、完成
- 失败重试管理
- 动态槽位填充
"""
import asyncio
import time
import logging
from typing import Dict, Set, Optional
from dataclasses import dataclass

from sentinel_agent.common import log_system_event


@dataclass
class TaskStatus:
    """任务状态"""
    challenge_code: str
    task: asyncio.Task
    start_time: float
    retry_count: int = 0
    attempt_history: list = None  # ⭐ 新增：历史尝试记录

    def __post_init__(self):
        if self.attempt_history is None:
            self.attempt_history = []


class ChallengeTaskManager:
    """挑战任务管理器 - 负责动态管理解题任务"""

    def __init__(self, max_retries: int = 2):
        """
        初始化任务管理器

        Args:
            max_retries: 最大重试次数（默认 2 次）
        """
        self.active_tasks: Dict[str, TaskStatus] = {}  # challenge_code -> TaskStatus
        self.completed_challenges: Set[str] = set()  # 已完成的题目代码
        self.failed_challenges: Dict[str, int] = {}  # challenge_code -> 失败次数
        # ⭐ 修复：attempt_history 存储 list 的深拷贝，避免并发修改
        self.attempt_history: Dict[str, list] = {}  # challenge_code -> 历史尝试记录（每次读取时深拷贝）
        self.lock = asyncio.Lock()  # 线程安全锁
        self.max_retries = max_retries

    async def add_task(self, challenge_code: str, task: asyncio.Task) -> bool:
        """
        添加新任务到管理器
        
        ⭐ 修复：在加锁状态下获取历史记录的深拷贝，避免并发修改
        """
        async with self.lock:
            if challenge_code in self.active_tasks:
                log_system_event(
                    f"[任务管理器] 任务已存在，跳过: {challenge_code}",
                    level=logging.WARNING
                )
                return False

            if challenge_code in self.completed_challenges:
                log_system_event(
                    f"[任务管理器] 题目已完成，跳过: {challenge_code}",
                    level=logging.INFO
                )
                return False

            retry_count = self.failed_challenges.get(challenge_code, 0)
            
            # ⭐ 深拷贝历史记录，防止后续修改时产生竞态条件
            attempt_history_copy = list(self.attempt_history.get(challenge_code, []))

            self.active_tasks[challenge_code] = TaskStatus(
                challenge_code=challenge_code,
                task=task,
                start_time=time.time(),
                retry_count=retry_count,
                attempt_history=attempt_history_copy
            )

            log_system_event(
                f"[任务管理器] 添加任务: {challenge_code} (重试次数: {retry_count})"
            )
            return True

    async def remove_task(self, challenge_code: str, success: bool = False, attempt_summary: Optional[Dict] = None):
        """
        移除任务

        Args:
            challenge_code: 题目代码
            success: 是否成功
            attempt_summary: 本次尝试的摘要（用于历史记录）
        """
        async with self.lock:
            if challenge_code in self.active_tasks:
                task_status = self.active_tasks.pop(challenge_code)
                elapsed = time.time() - task_status.start_time

                # ⭐ 记录本次尝试
                if attempt_summary:
                    if challenge_code not in self.attempt_history:
                        self.attempt_history[challenge_code] = []
                    self.attempt_history[challenge_code].append(attempt_summary)

                if success:
                    self.completed_challenges.add(challenge_code)
                    if challenge_code in self.failed_challenges:
                        del self.failed_challenges[challenge_code]
                    log_system_event(
                        f"[任务管理器] ✅ 任务完成: {challenge_code} (耗时: {elapsed:.1f}s)"
                    )
                else:
                    self.failed_challenges[challenge_code] = self.failed_challenges.get(challenge_code, 0) + 1
                    log_system_event(
                        f"[任务管理器] ❌ 任务失败: {challenge_code} (失败次数: {self.failed_challenges[challenge_code]})"
                    )

    async def get_status(self) -> Dict:
        """获取当前状态"""
        async with self.lock:
            return {
                "active_count": len(self.active_tasks),
                "completed_count": len(self.completed_challenges),
                "failed_count": len(self.failed_challenges),
                "active_tasks": list(self.active_tasks.keys()),
                "completed_tasks": list(self.completed_challenges),
                "failed_tasks": dict(self.failed_challenges)
            }

    async def is_completed(self, challenge_code: str) -> bool:
        """
        检查题目是否已完成（线程安全）

        Args:
            challenge_code: 题目代码

        Returns:
            True: 已完成
            False: 未完成
        """
        async with self.lock:
            return challenge_code in self.completed_challenges

    async def is_active(self, challenge_code: str) -> bool:
        """
        检查题目是否正在解决（线程安全）

        Args:
            challenge_code: 题目代码

        Returns:
            True: 正在解决
            False: 未在解决
        """
        async with self.lock:
            return challenge_code in self.active_tasks

    async def should_retry(self, challenge_code: str) -> bool:
        """
        判断是否应该重试（线程安全）

        Args:
            challenge_code: 题目代码

        Returns:
            True: 应该重试
            False: 已达最大重试次数或已完成
        """
        async with self.lock:
            if challenge_code in self.completed_challenges:
                return False

            retry_count = self.failed_challenges.get(challenge_code, 0)
            return retry_count < self.max_retries

    async def get_attempt_history(self, challenge_code: str) -> list:
        """
        获取题目的历史尝试记录（线程安全 + 深拷贝）

        Args:
            challenge_code: 题目代码

        Returns:
            历史尝试记录的深拷贝
        """
        async with self.lock:
            return list(self.attempt_history.get(challenge_code, []))

    async def get_retry_count(self, challenge_code: str) -> int:
        """
        获取题目的重试次数（线程安全）

        Args:
            challenge_code: 题目代码

        Returns:
            重试次数
        """
        async with self.lock:
            return self.failed_challenges.get(challenge_code, 0)
