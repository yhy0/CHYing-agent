"""CTF 比赛调度器基类 — Template Method 模式

核心职责（子类无需关心）：
1. 赛题管理: discover → filter → prioritize
2. 并发调度: Semaphore + asyncio.gather + 重试循环 + session rotation
3. Flag 提交: 结构化输出 + findings.log 多来源收集 + 去重
4. Hint 透传: contextvars callback 注入 solver 的 view_hint MCP 工具

子类只需实现：discover_challenges / start_challenge / stop_challenge / submit_flag
可选覆盖：download_attachments / get_hint / _should_skip / _on_solve_start / _on_solve_finish
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from ..common import log_system_event
from ..task_manager import ChallengeStats


class BaseCTFRunner(ABC):
    """CTF 比赛调度器基类"""

    def __init__(
        self,
        *,
        concurrency: int = 3,
        max_retries: int = 4,
        category_filter: Optional[str] = None,
        work_dir_name: str = "ctf",
    ):
        from ..runtime.singleton import get_config_manager
        self._config = get_config_manager().config
        self._stats = ChallengeStats()

        self._concurrency = concurrency
        self._max_retries = max_retries
        self._category_filter = category_filter
        self._semaphore = asyncio.Semaphore(concurrency)

        self._submitted_flags: dict[str, set[str]] = {}  # code -> {已成功提交的 flag, ...}
        self._total = self._solved = self._failed = 0

        self._work_dir = Path(f"agent-work/ctf/{work_dir_name}").resolve()
        self._work_dir.mkdir(parents=True, exist_ok=True)

    # ==================== 模板方法 ====================

    async def run(self):
        """模板方法: discover → filter → solve_all → summary"""
        challenges = await self.discover_challenges()
        if not challenges:
            log_system_event("[Runner] 无可用题目")
            return

        pending = self._filter_and_prioritize(challenges)
        # 应用 _should_skip 过滤（支持 resume/retry-errors）
        filtered = []
        for ch in pending:
            if not await self._should_skip(ch):
                filtered.append(ch)
        pending = filtered
        self._total = len(pending)
        if not pending:
            log_system_event("[Runner] 过滤后无待做题目")
            return

        log_system_event(
            f"[Runner] 开始做题: {self._total} 道, 并发={self._concurrency}"
        )
        await asyncio.gather(
            *(self._solve_one(ch) for ch in pending),
            return_exceptions=True,
        )
        self._print_summary()

    # ==================== 子类必须实现 ====================

    @abstractmethod
    async def discover_challenges(self) -> list[dict]:
        """发现所有题目，返回题目 dict 列表"""
        ...

    @abstractmethod
    async def start_challenge(self, challenge: dict) -> Optional[str]:
        """启动题目实例，返回 target_url (无需启动时返回 None)"""
        ...

    @abstractmethod
    async def stop_challenge(self, challenge: dict) -> None:
        """停止题目实例"""
        ...

    @abstractmethod
    async def submit_flag(self, challenge: dict, flag: str) -> bool:
        """提交 flag，返回是否正确"""
        ...

    # ==================== 子类可选覆盖 ====================

    async def download_attachments(self, challenge: dict, work_dir: Path) -> None:
        """下载题目附件到 work_dir。默认无操作。"""
        pass

    async def get_hint(self, challenge: dict) -> str:
        """获取题目提示。默认不支持。"""
        return "当前平台不支持 hint"

    async def _should_skip(self, challenge: dict) -> bool:
        """是否跳过此题？默认不跳过。用于 resume/retry-errors 等场景。"""
        return False

    async def _on_solve_start(self, challenge: dict, target_url: Optional[str]) -> None:
        """Hook: start_challenge 之后、做题之前。用于 dashboard 埋点等。"""
        pass

    async def _should_abort_after_start(
        self, challenge: dict, target_url: Optional[str],
    ) -> bool:
        """Hook: start_challenge 之后决定是否中止本轮。

        默认不拦截。某些平台在实例启动失败、题目已完成或未拿到入口地址时，
        可以覆盖此方法，避免继续进入 solver 浪费时间。
        """
        return False

    def _get_solve_timeout_seconds(self, challenge: dict) -> Optional[float]:
        """Hook: 单题完整求解流程的硬超时（秒）。

        默认不限制。子类可覆盖此方法，为某些平台增加
        「solver 超时 + 缓冲时间」的整体超时保护，避免实例名额被长期占满。
        """
        return None

    async def _on_solve_timeout(
        self, challenge: dict, timeout_seconds: float,
    ) -> None:
        """Hook: 单题完整求解流程触发硬超时时的回调。"""
        pass

    async def _on_solve_finish(
        self, challenge: dict, result: Optional[dict], duration_seconds: float,
    ) -> None:
        """Hook: 做题完成后、stop_challenge 之前。用于记录结果、保存 state 等。"""
        pass

    # ==================== 基类核心逻辑 ====================

    async def _solve_one(self, challenge: dict):
        """单题完整流程: start → solve → submit → stop"""
        async with self._semaphore:
            ch_id = str(challenge.get("id") or challenge.get("code", ""))
            name = challenge.get("name", ch_id)
            log_system_event(f"[Runner] 开始: {name} (id={ch_id})")

            target_url = await self.start_challenge(challenge)
            if await self._should_abort_after_start(challenge, target_url):
                return
            _t0 = time.monotonic()
            await self._on_solve_start(challenge, target_url)

            result = None
            try:
                try:
                    # 准备工作目录 + 下载附件
                    ch_work_dir = self._setup_work_dir(challenge)
                    await self.download_attachments(challenge, ch_work_dir)

                    # 构建 solver 需要的 challenge dict
                    ch_dict = self._build_challenge_dict(
                        challenge, target_url, ch_work_dir
                    )

                    # 注入 hint callback (contextvars 隔离)
                    from ..runtime.context import (
                        set_hint_callback, clear_hint_callback,
                        set_submit_flag_callback, clear_submit_flag_callback,
                    )

                    captured_challenge = challenge

                    async def _hint_callback():
                        return await self.get_hint(captured_challenge)

                    async def _submit_flag_callback(flag: str):
                        """将 agent 调用的 submit_flag MCP 工具桥接到 submit_flag 抽象方法。"""
                        ch_code = str(
                            captured_challenge.get("id") or captured_challenge.get("code", "")
                        )
                        # 去重：已通过此回调提交过的 flag 不再重复提交
                        if flag in self._submitted_flags.get(ch_code, set()):
                            return True, "Flag 已提交过（跳过重复提交）"
                        ok = await self.submit_flag(captured_challenge, flag)
                        if ok:
                            self._submitted_flags.setdefault(ch_code, set()).add(flag)
                        message = "Flag 正确！" if ok else "Flag 错误或已提交过"
                        return ok, message

                    async def _solve_pipeline():
                        nonlocal result
                        set_hint_callback(_hint_callback)
                        set_submit_flag_callback(_submit_flag_callback)
                        try:
                            result = await self._retry_solve(ch_dict)
                            await self._collect_and_submit_flags(
                                challenge, result, ch_work_dir
                            )
                        finally:
                            clear_hint_callback()
                            clear_submit_flag_callback()

                    solve_timeout = self._get_solve_timeout_seconds(challenge)
                    if solve_timeout and solve_timeout > 0:
                        async with asyncio.timeout(solve_timeout):
                            await _solve_pipeline()
                    else:
                        await _solve_pipeline()
                except asyncio.TimeoutError:
                    timeout_seconds = float(self._get_solve_timeout_seconds(challenge) or 0)
                    self._failed += 1
                    result = result or {
                        "success": False,
                        "timeout": True,
                        "error": "runner_timeout",
                    }
                    log_system_event(
                        f"[Runner] 单题硬超时，放弃本轮: {name} (id={ch_id})",
                        {"timeout_seconds": timeout_seconds},
                        level=logging.WARNING,
                    )
                    await self._on_solve_timeout(challenge, timeout_seconds)
            finally:
                duration = time.monotonic() - _t0
                try:
                    await self._on_solve_finish(challenge, result, duration)
                except Exception as e:
                    log_system_event(
                        f"[Runner] _on_solve_finish 异常: {e}",
                        level=logging.ERROR,
                    )
                await self.stop_challenge(challenge)

    async def _retry_solve(self, ch_dict: dict) -> Optional[dict]:
        """重试循环 + session rotation"""
        from ..challenge_solver import solve_single_challenge

        attempt = 0
        result = None
        attempt_history: list[dict] = []

        while attempt <= self._max_retries:
            if attempt > 0:
                log_system_event(
                    f"[Runner] 重试 {attempt}/{self._max_retries}: "
                    f"{ch_dict.get('challenge_code', '')}"
                )

            try:
                result = await solve_single_challenge(
                    challenge=ch_dict,
                    config=self._config,
                    stats=self._stats,
                    attempt_history=attempt_history if attempt > 0 else None,
                )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log_system_event(
                    f"[Runner] solve 异常: {e}", level=logging.ERROR,
                )

            if result and result.get("success"):
                self._solved += 1
                return result

            attempt_history.append({
                "attempt": attempt + 1, "strategy": "Orchestrator",
            })
            attempt += 1

        self._failed += 1
        return result

    # ---------- Flag 管理 ----------

    async def _collect_and_submit_flags(
        self, challenge: dict, result: Optional[dict], work_dir: Path,
    ):
        """多来源收集 flag + 去重提交"""
        flags: set[str] = set()

        # 来源 1: 结构化输出
        if result and result.get("flag"):
            flags.add(result["flag"])

        # 来源 2: findings.log
        findings_path = work_dir / "findings.log"
        if findings_path.exists():
            text = findings_path.read_text(errors="ignore")
            flags.update(re.findall(
                r"(?:flag|HTB|ctf|CTF)\{[^}]+\}", text, re.IGNORECASE,
            ))

        if not flags:
            return

        code = str(challenge.get("id") or challenge.get("code", ""))
        for flag in flags:
            if flag in self._submitted_flags.get(code, set()):
                continue

            try:
                ok = await self.submit_flag(challenge, flag)
                if ok:
                    self._submitted_flags.setdefault(code, set()).add(flag)
                    log_system_event(
                        f"[Runner] Flag 正确: {code} -> {flag[:40]}..."
                    )
            except Exception as e:
                log_system_event(
                    f"[Runner] submit 失败: {e}", level=logging.ERROR,
                )

    # ---------- 辅助 ----------

    def _build_challenge_dict(
        self, challenge: dict, target_url: Optional[str], work_dir: Path,
    ) -> dict:
        """构建 solve_single_challenge 需要的标准 challenge dict"""
        ch_id = str(challenge.get("id") or challenge.get("code", ""))
        category = self._get_category(challenge)
        name = challenge.get("name", ch_id)
        description = challenge.get("description", "")
        points = challenge.get("points", 0)

        files = [
            str(f.relative_to(work_dir))
            for f in work_dir.iterdir()
            if f.is_file() and not f.name.startswith(".")
        ]

        ch_dict: dict = {
            "challenge_code": ch_id,
            "category": category,
            "difficulty": challenge.get("difficulty", "unknown"),
            "points": points,
            "target_info": {"path": str(work_dir), "files": files},
            "_mode": "ctf-web" if category == "web" else "ctf",
        }

        if target_url:
            parsed = urlparse(target_url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            ch_dict["target_info"].update({
                "ip": parsed.hostname or "127.0.0.1",
                "port": [port],
                "urls": [target_url],
            })
            ch_dict["_target_url"] = target_url
            ch_dict["_target_urls"] = [target_url]

        prompt_parts = []
        if name:
            prompt_parts.append(f"题目名称: {name}")
        if description:
            prompt_parts.append(f"题目描述: {description}")
        if points:
            prompt_parts.append(f"分值: {points}")
        if prompt_parts:
            ch_dict["_prompt"] = "\n".join(prompt_parts)

        return ch_dict

    def _setup_work_dir(self, challenge: dict) -> Path:
        category = self._get_category(challenge)
        raw_name = challenge.get("name") or str(challenge.get("id", "unnamed"))
        safe_name = re.sub(r'[^\w\-]', '_', raw_name).lower()
        safe_name = re.sub(r'_+', '_', safe_name).strip('_')[:80]
        d = self._work_dir / category.capitalize() / safe_name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _filter_and_prioritize(self, challenges: list[dict]) -> list[dict]:
        pending = [c for c in challenges if not c.get("solved")]
        if self._category_filter:
            cat_lower = self._category_filter.lower()
            pending = [
                c for c in pending
                if self._get_category(c) == cat_lower
            ]
        pending.sort(key=lambda c: c.get("points", 0))
        return pending

    @staticmethod
    def _get_category(challenge: dict) -> str:
        cat = challenge.get("category", "web")
        if isinstance(cat, dict):
            cat = cat.get("name", "web")
        return str(cat).lower()

    @staticmethod
    def _extract_url(text: str) -> Optional[str]:
        """从文本中提取 target URL"""
        match = re.search(r'https?://[\w.\-]+:\d+', text)
        if match:
            return match.group()
        for m in re.finditer(r'https?://[\w.\-]+(?:/\S*)?', text):
            url = m.group()
            if any(s in url for s in (".amazonaws.com", "github.com", "cdn.")):
                continue
            return url
        return None

    def _print_summary(self):
        log_system_event("=" * 60)
        log_system_event(
            f"[Runner] 统计: 共 {self._total} 题, "
            f"解出 {self._solved}, 失败 {self._failed}, "
            f"跳过 {self._total - self._solved - self._failed}"
        )
        if self._submitted_flags:
            log_system_event("[Runner] 已提交 Flag:")
            for code, flags in self._submitted_flags.items():
                for flag in flags:
                    log_system_event(f"  {code}: {flag[:60]}...")
        log_system_event("=" * 60)
