"""
动态题目扫描器
===============

实时监控 CTF 目录，自动发现新增题目并添加到任务队列。

功能：
1. 定期扫描 agent-work/ctf/ 目录
2. 检查数据库中的题目执行状态
3. 跳过已完成（SUCCESS）或正在执行（RUNNING）的题目
4. 自动将新题目添加到任务管理器

设计原则：
- 不重复添加已有题目
- 遵循任务管理器的并发限制
- 支持运行时题目动态发布（CTF 比赛中常见场景）
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime

from sqlalchemy.orm import Session, selectinload

from chying_agent.contest.multi_target import (
    auto_detect_ctf_challenges,
    parse_web_challenges,
    parse_directory_challenges,
)
from chying_agent.db import get_db, Challenge, Execution, ExecutionStatus
from chying_agent.common import log_system_event


class DynamicChallengeScanner:
    """
    动态题目扫描器

    定期扫描 CTF 目录，发现新增题目并自动添加到任务队列。
    """

    def __init__(
        self,
        max_retries: int,
        solver_callback,
        ctf_dir: Optional[str] = None,
        scan_interval: int = 60,
    ):
        """
        初始化扫描器

        Args:
            max_retries: 最大重试次数（用于判断题目是否达到重试上限）
            solver_callback: 解题回调函数，签名为 async def solve(challenge: dict) -> None
            ctf_dir: CTF 目录路径（默认 agent-work/ctf）
            scan_interval: 扫描间隔（秒）
        """
        self.max_retries = max_retries
        self.solver_callback = solver_callback
        self.ctf_dir = ctf_dir
        self.scan_interval = scan_interval

        self._running = False
        self._scan_task: Optional[asyncio.Task] = None
        self._scanned_challenges: Set[str] = set()  # 已扫描过的题目代码
        self._known_urls: Set[str] = set()  # 已知的 URL（用于 Web 题目去重）
        self._last_scan_time: Optional[datetime] = None

        # 题目类型配置（用于动态添加）
        self._category_configs: Dict[str, dict] = {}

    def add_category_config(
        self, category: str, challenges: List[Dict], concurrency: int
    ) -> None:
        """
        注册题目类型配置（用于动态添加题目时的参数）

        Args:
            category: 题目类型 (web, pwn, misc, crypto)
            challenges: 初始题目列表
            concurrency: 并发数
        """
        self._category_configs[category] = {
            "challenges": challenges,
            "concurrency": concurrency,
            "semaphore": None,  # 由 MultiTargetManager 管理
        }

        # 将初始题目标记为已扫描，避免重复处理
        for challenge in challenges:
            challenge_code = challenge.get("challenge_code")
            if challenge_code:
                self._scanned_challenges.add(challenge_code)

            # 对于 Web 题目，同时记录 URL 用于去重
            if category == "web":
                url = challenge.get("_target_url")
                if url:
                    self._known_urls.add(url)

    async def start(self) -> None:
        """启动扫描器"""
        if self._running:
            log_system_event("[动态扫描] 扫描器已在运行", level=logging.WARNING)
            return

        self._running = True
        self._scan_task = asyncio.create_task(self._scan_loop())
        log_system_event(
            f"[动态扫描] ✅ 扫描器已启动",
            {"扫描间隔": f"{self.scan_interval}秒", "CTF目录": self.ctf_dir or "agent-work/ctf"},
        )

    async def stop(self) -> None:
        """停止扫描器"""
        self._running = False

        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass

        log_system_event("[动态扫描] 扫描器已停止")

    async def _scan_loop(self) -> None:
        """扫描循环"""
        try:
            while self._running:
                try:
                    await self._scan_for_new_challenges()
                    self._last_scan_time = datetime.now()
                except Exception as e:
                    log_system_event(
                        f"[动态扫描] ⚠️ 扫描异常: {str(e)}",
                        level=logging.ERROR,
                    )

                # 等待下次扫描
                for _ in range(self.scan_interval * 10):  # 0.1s 检查一次
                    if not self._running:
                        break
                    await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            log_system_event("[动态扫描] 扫描循环被取消")
            raise

    async def _scan_for_new_challenges(self) -> None:
        """扫描新题目"""
        # 1. 检测当前目录中的题目
        detected = auto_detect_ctf_challenges(ctf_dir=self.ctf_dir)

        if not detected.get("found"):
            return

        # 2. 解析各类型题目
        new_challenges: List[Dict] = []

        # Web 题目
        if detected.get("web_file"):
            try:
                web_challenges = parse_web_challenges(detected["web_file"])
                new_challenges.extend(web_challenges)
            except Exception as e:
                log_system_event(
                    f"[动态扫描] ⚠️ 解析 Web 题目失败: {e}",
                    level=logging.WARNING,
                )

        # PWN 题目
        if detected.get("pwn_dir"):
            try:
                pwn_challenges = parse_directory_challenges(
                    detected["pwn_dir"], "pwn"
                )
                new_challenges.extend(pwn_challenges)
            except Exception as e:
                log_system_event(
                    f"[动态扫描] ⚠️ 解析 PWN 题目失败: {e}",
                    level=logging.WARNING,
                )

        # Misc 题目
        if detected.get("misc_dir"):
            try:
                misc_challenges = parse_directory_challenges(
                    detected["misc_dir"], "misc"
                )
                new_challenges.extend(misc_challenges)
            except Exception as e:
                log_system_event(
                    f"[动态扫描] ⚠️ 解析 Misc 题目失败: {e}",
                    level=logging.WARNING,
                )

        # Crypto 题目
        if detected.get("crypto_dir"):
            try:
                crypto_challenges = parse_directory_challenges(
                    detected["crypto_dir"], "crypto"
                )
                new_challenges.extend(crypto_challenges)
            except Exception as e:
                log_system_event(
                    f"[动态扫描] ⚠️ 解析 Crypto 题目失败: {e}",
                    level=logging.WARNING,
                )

        # 3. 筛选并添加新题目
        if new_challenges:
            await self._filter_and_add_challenges(new_challenges)

    async def _filter_and_add_challenges(self, challenges: List[Dict]) -> None:
        """
        筛选并添加新题目

        筛选规则：
        - 跳过已扫描过的题目
        - 跳过已完成（SUCCESS）的题目
        - 跳过正在运行（RUNNING）的题目
        - 对于失败的题目，根据重试策略判断是否应该重试
        - Web 题目使用 URL 去重（因为 challenge_code 会因目录存在而变化）

        Args:
            challenges: 解析得到的题目列表
        """
        added_count = 0
        skipped: Dict[str, List[str]] = {
            "已扫描": [],
            "已知URL": [],
            "已完成": [],
            "运行中": [],
            "达到重试上限": [],
        }

        # 使用数据库查询获取题目状态
        with get_db() as db:
            for challenge in challenges:
                challenge_code = challenge.get("challenge_code")

                if not challenge_code:
                    continue

                # 检查是否已扫描过
                if challenge_code in self._scanned_challenges:
                    skipped["已扫描"].append(challenge_code)
                    continue

                # Web 题目使用 URL 去重（因为 challenge_code 会因目录存在而变化）
                category = challenge.get("category")
                url = challenge.get("_target_url")
                if category == "web" and url and url in self._known_urls:
                    log_system_event(
                        f"[动态扫描] 跳过已知URL题目: {challenge_code} (URL: {url})"
                    )
                    skipped["已知URL"].append(challenge_code)
                    self._scanned_challenges.add(challenge_code)
                    continue

                # 查询题目的执行状态
                db_challenge = (
                    db.query(Challenge)
                    .filter(Challenge.challenge_code == challenge_code)
                    .options(selectinload(Challenge.executions))
                    .first()
                )

                if db_challenge:
                    executions = db_challenge.executions

                    if not executions:
                        # 数据库中有记录但没有执行记录，可能是新增失败后重启，继续处理
                        pass
                    else:
                        # 检查最新的执行状态
                        latest_exec = max(executions, key=lambda e: e.started_at)

                        if latest_exec.status == ExecutionStatus.SUCCESS:
                            log_system_event(
                                f"[动态扫描] 跳过已完成题目: {challenge_code}"
                            )
                            skipped["已完成"].append(challenge_code)
                            self._scanned_challenges.add(challenge_code)
                            continue

                        if latest_exec.status == ExecutionStatus.RUNNING:
                            log_system_event(
                                f"[动态扫描] 跳过运行中题目: {challenge_code}"
                            )
                            skipped["运行中"].append(challenge_code)
                            self._scanned_challenges.add(challenge_code)
                            continue

                        # 失败的题目：检查是否已经达到重试上限
                        failed_count = sum(
                            1
                            for e in executions
                            if e.status
                            in [
                                ExecutionStatus.FAILED,
                                ExecutionStatus.TIMEOUT,
                                ExecutionStatus.CANCELLED,
                            ]
                        )

                        if failed_count >= self.max_retries:
                            log_system_event(
                                f"[动态扫描] 跳过已达重试上限的题目: {challenge_code} (失败 {failed_count} 次)"
                            )
                            skipped["达到重试上限"].append(challenge_code)
                            self._scanned_challenges.add(challenge_code)
                            continue

                # 通过所有检查，添加题目
                await self._add_single_challenge(challenge, db)
                self._scanned_challenges.add(challenge_code)
                # 对于 Web 题目，将 URL 记录为已知，避免重复
                if category == "web" and url:
                    self._known_urls.add(url)
                added_count += 1

        # 记录扫描结果
        if added_count > 0 or any(skipped.values()):
            log_system_event(
                f"[动态扫描] 📋 扫描结果",
                {
                    "新增题目": added_count,
                    "跳过-已扫描": len(skipped["已扫描"]),
                    "跳过-已知URL": len(skipped["已知URL"]),
                    "跳过-已完成": len(skipped["已完成"]),
                    "跳过-运行中": len(skipped["运行中"]),
                    "跳过-到达上限": len(skipped["达到重试上限"]),
                },
            )

            # 打印跳过的详情（如果有新增题目）
            if added_count > 0:
                for reason, codes in skipped.items():
                    if codes:
                        log_system_event(
                            f"[动态扫描] 跳过 {reason}: {', '.join(codes)}"
                            + (f" ... 等 {len(codes)} 题" if len(codes) > 5 else ""),
                            level=logging.INFO,
                        )

    async def _add_single_challenge(
        self, challenge: Dict, db: Session
    ) -> None:
        """
        添加单个题目到任务队列

        Args:
            challenge: 题目信息
            db: 数据库会话
        """
        challenge_code = challenge.get("challenge_code")
        category = challenge.get("category", "unknown")

        # 直接调用 solver_callback（由 MultiTargetManager 的 _solve_dynamic_challenge 处理）
        # 通过创建后台任务来异步执行
        asyncio.create_task(
            self.solver_callback(challenge),
            name=f"dynamic_{challenge_code}",
        )

        log_system_event(
            f"[动态扫描] ✅ 添加新题目: {challenge_code}",
            {"类型": category},
        )

    async def get_scan_status(self) -> Dict:
        """
        获取扫描器状态

        Returns:
            扫描器状态信息
        """
        return {
            "running": self._running,
            "scanned_count": len(self._scanned_challenges),
            "_last_scan_time": self._last_scan_time.isoformat()
            if self._last_scan_time
            else None,
            "scan_interval": self.scan_interval,
        }

    async def force_scan_now(self) -> Dict:
        """
        立即执行一次扫描（外部调用）

        Returns:
            扫描结果统计
        """
        try:
            await self._scan_for_new_challenges()
            self._last_scan_time = datetime.now()
            return {"success": True, "scanned_time": self._last_scan_time.isoformat()}
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }
