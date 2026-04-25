"""第二届腾讯云黑客松智能渗透挑战赛适配器

API 接口:
  GET  /api/challenges       → 获取赛题列表（含关卡信息）
  POST /api/start_challenge  → 启动赛题实例（最多同时 3 个）
  POST /api/stop_challenge   → 停止赛题实例
  POST /api/submit           → 提交 Flag（支持多 Flag 得分点）
  POST /api/hint             → 查看赛题提示（扣 10% 分数）

认证方式: Agent-Token header
频率限制: 每队每秒最多 3 次（所有接口共享）
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

import httpx

from ..common import log_system_event
from .base import BaseCTFRunner


class TencentCloudCTFRunner(BaseCTFRunner):
    """腾讯云黑客松智能渗透挑战赛 — HTTP API 适配器

    特点:
    - 关卡制: 当前关卡所有题目完成后解锁下一关卡
    - 多 Flag 得分点: 一道题可能有多个 Flag
    - 实例上限: 同时运行最多 3 个赛题实例
    - 频率限制: 每秒最多 3 次 API 调用（自动限速）
    """

    def __init__(
        self,
        server_host: str,
        agent_token: str,
        *,
        use_hints: bool = True,
        priority_level: int | None = None,
        **kwargs,
    ):
        """
        Args:
            server_host: 平台服务器地址 (如 "1.2.3.4:8080")
            agent_token: 队伍的 Agent Token
            use_hints: 是否允许使用提示（会扣 10% 分数）
            priority_level: 优先做的关卡号（如 3），该关卡题目排最前
            **kwargs: 传递给 BaseCTFRunner 的参数
        """
        # 平台同时最多运行 3 个实例，并发数不应超过 3
        concurrency = min(kwargs.pop("concurrency", 3), 3)
        super().__init__(
            concurrency=concurrency,
            work_dir_name="tencent_cloud",
            **kwargs,
        )

        # 处理 server_host，确保有协议前缀
        if not server_host.startswith(("http://", "https://")):
            server_host = f"http://{server_host}"
        self._base_url = server_host.rstrip("/") + "/api"
        self._agent_token = agent_token
        self._use_hints = use_hints
        self._priority_level = priority_level

        # 官方要求所有接口共享 3 req/s。
        # 用全局锁 + 最小间隔做稳定节流，优先避免正式比赛时打出 429。
        self._api_lock = asyncio.Lock()
        self._min_request_interval = 0.36
        self._last_request_started_at = 0.0
        self._http_client: httpx.AsyncClient | None = None

        # 记录当前关卡和赛题元数据（code -> challenge_info）
        self._current_level = 1
        self._challenge_meta: dict[str, dict] = {}
        self._seen_challenge_codes: set[str] = set()
        self._abandoned_codes: set[str] = set()
        self._attempt_counts: dict[str, int] = {}
        self._solve_timeout_seconds = int(self._config.runtime.single_task_timeout) + 180
        self._unlock_poll_attempts = 3
        self._unlock_poll_interval_seconds = 10
        self._retry_cooldown_seconds = 60

    # ==================== HTTP 客户端 ====================

    def _get_headers(self) -> dict[str, str]:
        return {
            "Agent-Token": self._agent_token,
            "Content-Type": "application/json",
        }

    async def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=60)
        return self._http_client

    async def _close_http_client(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def _throttle_api(self) -> None:
        """全局 API 节流：确保所有接口共享 3 req/s。"""
        async with self._api_lock:
            now = time.monotonic()
            wait = self._min_request_interval - (now - self._last_request_started_at)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_started_at = time.monotonic()

    @staticmethod
    def _is_retryable_business_error(status_code: int, message: str) -> bool:
        msg = (message or "").strip()
        if status_code in {429, 502, 503}:
            return True
        if status_code == 400 and "切换中" in msg:
            return True
        return False

    def _build_platform_snapshot(self, challenges: list[dict]) -> dict[str, Any]:
        flag_progress = {}
        solved_codes = set()
        visible_codes = set()

        for ch in challenges:
            code = str(ch.get("code") or ch.get("id") or "")
            if not code:
                continue
            visible_codes.add(code)
            got = int(ch.get("flag_got_count", 0) or 0)
            total = int(ch.get("flag_count", 0) or 0)
            flag_progress[code] = (got, total)
            if ch.get("solved"):
                solved_codes.add(code)

        return {
            "current_level": int(self._current_level or 0),
            "visible_codes": visible_codes,
            "solved_codes": solved_codes,
            "flag_progress": flag_progress,
        }

    @staticmethod
    def _has_platform_progress(before: dict[str, Any], after: dict[str, Any]) -> bool:
        if after["current_level"] > before["current_level"]:
            return True
        if after["visible_codes"] != before["visible_codes"]:
            return True
        if after["solved_codes"] != before["solved_codes"]:
            return True

        for code, (got, _total) in after["flag_progress"].items():
            prev_got = before["flag_progress"].get(code, (0, 0))[0]
            if got > prev_got:
                return True
        return False

    async def _request(
        self,
        method: str,
        path: str,
        json_data: dict | None = None,
    ) -> dict[str, Any]:
        """发送 API 请求，自动节流 + 重试瞬时错误。

        Returns:
            API 响应 JSON dict
        Raises:
            RuntimeError: API 返回非 200 状态码或 code != 0
        """
        url = f"{self._base_url}{path}"

        client = await self._get_http_client()
        last_error: str | None = None

        for attempt in range(5):
            try:
                await self._throttle_api()

                if method.upper() == "GET":
                    resp = await client.get(url, headers=self._get_headers())
                else:
                    resp = await client.post(
                        url, headers=self._get_headers(), json=json_data or {},
                    )
            except (httpx.TimeoutException, httpx.NetworkError, httpx.TransportError) as e:
                last_error = str(e)
                wait = 1.0 + attempt * 0.5
                log_system_event(
                    f"[TencentCloud] API 请求异常，等待 {wait}s 重试: {method} {path}",
                    {"error": str(e)},
                    level=logging.WARNING,
                )
                await asyncio.sleep(wait)
                continue

            if resp.status_code != 200:
                body = (
                    resp.json()
                    if resp.headers.get("content-type", "").startswith("application/json")
                    else {}
                )
                msg = body.get("message", resp.text[:200])
                if self._is_retryable_business_error(resp.status_code, msg):
                    wait = 1.0 + attempt * 0.5
                    log_system_event(
                        f"[TencentCloud] API 可重试错误，等待 {wait}s 重试: {method} {path}",
                        {"status_code": resp.status_code, "message": msg},
                        level=logging.WARNING,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise RuntimeError(
                    f"API {method} {path} 返回 {resp.status_code}: {msg}"
                )

            data = resp.json()
            if data.get("code") != 0:
                msg = data.get("message", "unknown")
                if self._is_retryable_business_error(400, msg):
                    wait = 1.0 + attempt * 0.5
                    log_system_event(
                        f"[TencentCloud] API 业务态可重试，等待 {wait}s 重试: {method} {path}",
                        {"message": msg},
                        level=logging.WARNING,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise RuntimeError(
                    f"API {method} {path} 业务错误: {msg}"
                )
            return data

        if last_error:
            raise RuntimeError(f"API {method} {path} 连续请求异常: {last_error}")
        raise RuntimeError(f"API {method} {path} 连续重试失败")

    # ==================== 子类实现 ====================

    async def discover_challenges(self) -> list[dict]:
        """GET /api/challenges → 获取赛题列表"""
        resp = await self._request("GET", "/challenges")
        data = resp.get("data", {})

        current_level = int(data.get("current_level", 1) or 1)
        self._current_level = current_level
        total = int(data.get("total_challenges", 0) or 0)
        solved = int(data.get("solved_challenges", 0) or 0)

        log_system_event(
            f"[TencentCloud] 当前关卡: {current_level}, "
            f"总题数: {total}, 已解: {solved}"
        )

        challenges = data.get("challenges", [])
        result = []

        for ch in challenges:
            code = ch.get("code", "")
            if code:
                self._seen_challenge_codes.add(code)
            # 缓存元数据
            self._challenge_meta[code] = ch

            total_score = int(ch.get("total_score", 0) or 0)
            total_got_score = int(ch.get("total_got_score", 0) or 0)
            flag_count = int(ch.get("flag_count", 0) or 0)
            flag_got_count = int(ch.get("flag_got_count", 0) or 0)
            remaining_score = max(total_score - total_got_score, 0)

            # 转换为 BaseCTFRunner 期望的格式
            is_solved = flag_count > 0 and flag_got_count >= flag_count
            challenge_level = int(ch.get("level", 1) or 1)
            initial_category = ch.get("category")
            if not initial_category:
                initial_category = "unknown" if challenge_level >= 3 else "web"

            challenge_dict = {
                "code": code,
                "id": code,  # BaseCTFRunner 会用 id 或 code
                "title": ch.get("title", code),
                "name": ch.get("title", code),
                "description": ch.get("description", ""),
                "category": initial_category,
                "difficulty": ch.get("difficulty", "unknown"),
                "points": total_score,
                "total_score": total_score,
                "total_got_score": total_got_score,
                "remaining_score": remaining_score,
                "level": challenge_level,
                "solved": is_solved,
                "flag_count": flag_count,
                "flag_got_count": flag_got_count,
                "hint_viewed": ch.get("hint_viewed", False),
                "instance_status": ch.get("instance_status", "stopped"),
                "entrypoint": ch.get("entrypoint"),
            }
            result.append(challenge_dict)

        log_system_event(
            f"[TencentCloud] 获取到 {len(result)} 道题目, "
            f"待做 {sum(1 for c in result if not c['solved'])} 道"
        )

        # ── 安全保险：已解决但实例仍在运行的题目，自动停止释放资源 ──
        # 避免已通关的题目占用实例配额（最多同时 3 个），影响新题目启动
        for ch in result:
            if (
                ch.get("solved")
                and ch.get("instance_status") == "running"
            ):
                code = ch.get("code", "")
                log_system_event(
                    f"[TencentCloud] 已解决题目 {code} 实例仍在运行，自动停止释放配额"
                )
                try:
                    await self._request("POST", "/stop_challenge", {"code": code})
                    if code in self._challenge_meta:
                        self._challenge_meta[code]["instance_status"] = "stopped"
                    ch["instance_status"] = "stopped"
                    log_system_event(f"[TencentCloud] 已停止已解决题目实例: {code}")
                except Exception as e:
                    log_system_event(
                        f"[TencentCloud] 停止已解决题目实例失败 ({code}): {e}",
                        level=logging.WARNING,
                    )

        return result

    async def start_challenge(self, challenge: dict) -> Optional[str]:
        """POST /api/start_challenge → 启动赛题实例，返回 target_url"""
        code = challenge.get("code") or challenge.get("id", "")

        # 如果实例已在运行且有入口地址，直接复用
        if challenge.get("instance_status") == "running" and challenge.get("entrypoint"):
            urls = challenge["entrypoint"]
            target = self._entrypoint_to_url(urls[0]) if urls else None
            if target:
                log_system_event(f"[TencentCloud] 复用已运行实例: {code} → {target}")
                return target

        try:
            resp = await self._request("POST", "/start_challenge", {"code": code})
            resp_data = resp.get("data")

            # 赛题已全部完成
            if isinstance(resp_data, dict) and resp_data.get("already_completed"):
                log_system_event(f"[TencentCloud] 赛题已全部完成: {code}")
                return None

            # 正常返回入口地址列表
            if isinstance(resp_data, list) and resp_data:
                target = self._entrypoint_to_url(resp_data[0])
                log_system_event(f"[TencentCloud] 实例启动: {code} → {target}")
                return target

            log_system_event(
                f"[TencentCloud] 实例启动但未返回入口: {code}, data={resp_data}",
                level=logging.WARNING,
            )
            return None

        except RuntimeError as e:
            err_msg = str(e)
            # 如果超出实例上限，尝试停掉一个已解出的实例再启动
            if "超出" in err_msg or "上限" in err_msg:
                log_system_event(
                    f"[TencentCloud] 实例数超限，尝试释放资源后重试: {code}",
                    level=logging.WARNING,
                )
                await self._release_one_instance(code)
                # 再试一次
                try:
                    resp = await self._request(
                        "POST", "/start_challenge", {"code": code},
                    )
                    resp_data = resp.get("data")
                    if isinstance(resp_data, list) and resp_data:
                        target = self._entrypoint_to_url(resp_data[0])
                        log_system_event(
                            f"[TencentCloud] 释放后启动成功: {code} → {target}"
                        )
                        return target
                except Exception as retry_err:
                    log_system_event(
                        f"[TencentCloud] 释放后重试仍失败: {retry_err}",
                        level=logging.ERROR,
                    )
            else:
                log_system_event(
                    f"[TencentCloud] start_challenge 失败: {e}",
                    level=logging.ERROR,
                )
            return None

    async def _should_abort_after_start(
        self, challenge: dict, target_url: Optional[str],
    ) -> bool:
        if target_url:
            return False

        code = challenge.get("code") or challenge.get("id", "")
        log_system_event(
            f"[TencentCloud] 未获得实例入口，跳过本轮求解: {code}",
            level=logging.WARNING,
        )
        return True

    def _get_solve_timeout_seconds(self, challenge: dict) -> Optional[float]:
        return float(self._solve_timeout_seconds)

    async def _on_solve_timeout(
        self, challenge: dict, timeout_seconds: float,
    ) -> None:
        code = challenge.get("code") or challenge.get("id", "")
        self._abandoned_codes.add(str(code))
        log_system_event(
            f"[TencentCloud] 题目硬超时，已标记为本轮放弃: {code}",
            {"timeout_seconds": timeout_seconds},
            level=logging.WARNING,
        )

    async def stop_challenge(self, challenge: dict) -> None:
        """POST /api/stop_challenge → 停止赛题实例

        多 Flag 题特殊处理：若当前 flag_got_count > 0 且仍有未收集的得分点，
        保留实例继续运行，让下一轮调度复用同一实例（start_challenge 会检测
        instance_status=running 并直接返回已有入口地址）。
        """
        code = challenge.get("code") or challenge.get("id", "")

        # ── 多 Flag 保活检查 ──────────────────────────────────────────────────
        # 优先使用 submit_flag 更新后的 _challenge_meta 数据（最新状态）
        meta = self._challenge_meta.get(str(code))
        if meta is not None:
            flag_count = int(meta.get("flag_count", 0) or 0)
            flag_got_count = int(meta.get("flag_got_count", 0) or 0)
            # flag_count > 1 → 多 Flag 题；0 < got < total → 还有剩余得分点
            if flag_count > 1 and 0 < flag_got_count < flag_count:
                remaining = flag_count - flag_got_count
                log_system_event(
                    f"[TencentCloud] 多 Flag 题 {code} 还有 {remaining} 个得分点未收集 "
                    f"({flag_got_count}/{flag_count})，保留实例运行以便下轮复用",
                    {"code": code, "flag_got": flag_got_count, "flag_total": flag_count},
                )
                return  # 不停止实例，保持容器存活
        # ─────────────────────────────────────────────────────────────────────

        try:
            await self._request("POST", "/stop_challenge", {"code": code})
            if code in self._challenge_meta:
                self._challenge_meta[code]["instance_status"] = "stopped"
            log_system_event(f"[TencentCloud] 实例已停止: {code}")
        except Exception as e:
            # 停止失败不应阻塞后续流程
            log_system_event(
                f"[TencentCloud] stop_challenge 失败 ({code}): {e}",
                level=logging.WARNING,
            )

    async def submit_flag(self, challenge: dict, flag: str) -> bool:
        """POST /api/submit → 提交 Flag"""
        code = challenge.get("code") or challenge.get("id", "")
        try:
            resp = await self._request(
                "POST", "/submit", {"code": code, "flag": flag},
            )
            result = resp.get("data", {})
            correct = result.get("correct", False)
            message = result.get("message", "")

            log_level = logging.INFO if correct else logging.WARNING
            log_system_event(
                f"[TencentCloud] submit({code}): "
                f"{'✓ 正确' if correct else '✗ 错误'} — {message}",
                {
                    "flag_got": result.get("flag_got_count", 0),
                    "flag_total": result.get("flag_count", 0),
                },
                level=log_level,
            )

            # 检查是否解锁新关卡
            if "解锁新的关卡" in message:
                log_system_event(
                    "[TencentCloud] 🎉 解锁新关卡！",
                    level=logging.INFO,
                )

            # 同步最新平台进度到本地缓存，避免后续排序/释放实例继续使用旧值。
            meta = self._challenge_meta.get(code)
            if meta is not None and correct:
                if result.get("flag_got_count") is not None:
                    meta["flag_got_count"] = result.get(
                        "flag_got_count", meta.get("flag_got_count", 0),
                    )
                if result.get("flag_count") is not None:
                    meta["flag_count"] = result.get(
                        "flag_count", meta.get("flag_count", 0),
                    )

            return correct

        except RuntimeError as e:
            log_system_event(
                f"[TencentCloud] submit_flag 失败 ({code}): {e}",
                level=logging.ERROR,
            )
            return False

    async def get_hint(self, challenge: dict) -> str:
        """POST /api/hint → 获取赛题提示（扣 10% 分数）"""
        if not self._use_hints:
            return "提示功能已禁用（查看提示会扣 10% 分数）"

        cached_hint = str(
            challenge.get("_hint") or challenge.get("hint_content") or ""
        ).strip()
        if cached_hint:
            return cached_hint

        code = challenge.get("code") or challenge.get("id", "")
        try:
            resp = await self._request("POST", "/hint", {"code": code})
            result = resp.get("data", {})
            hint = result.get("hint_content")
            if hint:
                challenge["_hint"] = hint
                challenge["hint_content"] = hint
                challenge["hint_viewed"] = True
                log_system_event(f"[TencentCloud] 获取提示 ({code}): {hint[:100]}...")
                return hint
            return "该赛题暂无提示"
        except RuntimeError as e:
            log_system_event(
                f"[TencentCloud] get_hint 失败 ({code}): {e}",
                level=logging.WARNING,
            )
            return f"获取提示失败: {e}"

    async def _on_solve_start(self, challenge: dict, target_url: Optional[str]) -> None:
        """实例启动后立即预取 hint，并透传给后续 solver。"""
        if not self._use_hints:
            return

        code = challenge.get("code") or challenge.get("id", "")
        try:
            hint = await self.get_hint(challenge)
        except Exception as e:
            log_system_event(
                f"[TencentCloud] 预取 hint 失败 ({code}): {e}",
                level=logging.WARNING,
            )
            return

        if (
            not hint
            or hint == "该赛题暂无提示"
            or hint.startswith("获取提示失败:")
            or hint.startswith("提示功能已禁用")
        ):
            return

        challenge["_hint"] = hint
        challenge["hint_content"] = hint

        desc = str(challenge.get("description") or "").strip()
        if hint not in desc:
            challenge["description"] = (
                f"{desc}\n\n[比赛提示]\n{hint}".strip()
                if desc else f"[比赛提示]\n{hint}"
            )

        log_system_event(
            f"[TencentCloud] 已预取 hint 并注入题目上下文: {code}"
        )

    # ==================== 覆盖基类方法 ====================

    async def _retry_solve(self, ch_dict: dict) -> Optional[dict]:
        """多 Flag 感知的重试循环。

        每轮 solve 完成后：
        - 若找到 flag → 立即提交到平台 → 刷新 flag_got_count
        - 若 flag_count > 1 且 flag_got_count < flag_count → 更新 ch_dict 的
          _prompt（进度提示），重置 attempt 计数，继续在同一实例上做下一得分点
        - 直到所有得分点收集完毕 或 超时 或 连续失败耗尽重试次数

        关键设计：solver 返回 flag 后需**先提交**再检查平台进度，否则
        _challenge_meta 中的 flag_got_count 尚未更新，会导致误判为"还有
        剩余得分点"而无限循环（尤其对单 Flag 题）。
        """
        from ..challenge_solver import solve_single_challenge
        import re

        code = ch_dict.get("challenge_code", "")
        attempt = 0
        result = None
        attempt_history: list[dict] = []

        # 多 Flag 外层循环：每找到一个得分点就重置 attempt 继续
        flag_round = 0

        while True:
            while attempt <= self._max_retries:
                if attempt > 0:
                    log_system_event(
                        f"[TencentCloud] 重试 {attempt}/{self._max_retries}: {code}"
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
                        f"[TencentCloud] solve 异常: {e}", level=logging.ERROR,
                    )

                if result and result.get("success"):
                    break  # 找到 flag，跳出内层 attempt 循环

                attempt_history.append({
                    "attempt": attempt + 1, "strategy": "Orchestrator",
                })
                attempt += 1

            # ── 内层重试结束：检查是否找到 flag ───────────────────────────
            if not (result and result.get("success")):
                # 本轮所有重试耗尽仍未找到 flag
                if flag_round == 0:
                    self._failed += 1
                # 若之前已找到部分 flag，_solved 已计，不重复计
                return result

            # 找到了 flag
            if flag_round == 0:
                self._solved += 1

            flag_round += 1

            # ── 先提交 flag 到平台，确保 _challenge_meta 得到更新 ────────
            # 这一步至关重要：submit_flag 成功后会同步 flag_got_count 到
            # _challenge_meta，之后的进度检查才能拿到正确值。
            found_flag = result.get("flag")
            if found_flag:
                challenge_for_submit = self._challenge_meta.get(str(code), {})
                if not challenge_for_submit:
                    challenge_for_submit = {"code": code}
                else:
                    challenge_for_submit = dict(challenge_for_submit)
                    challenge_for_submit.setdefault("code", code)

                already_submitted = self._submitted_flags.get(str(code), set())
                if found_flag not in already_submitted:
                    try:
                        ok = await self.submit_flag(challenge_for_submit, found_flag)
                        if ok:
                            self._submitted_flags.setdefault(str(code), set()).add(found_flag)
                            log_system_event(
                                f"[TencentCloud] _retry_solve 提交 Flag 成功: {code} -> {found_flag[:40]}..."
                            )
                    except Exception as e:
                        log_system_event(
                            f"[TencentCloud] _retry_solve 提交 Flag 失败: {e}",
                            level=logging.ERROR,
                        )

            # ── 查看平台最新 flag 进度 ──────────────────────────────────
            meta = self._challenge_meta.get(str(code))
            if meta is None:
                return result

            flag_count = int(meta.get("flag_count", 1) or 1)
            flag_got_count = int(meta.get("flag_got_count", 0) or 0)

            # 单 Flag 题：不进入多 Flag 循环，直接返回
            if flag_count <= 1:
                return result

            if flag_got_count >= flag_count:
                # 全部得分点已收集，结束
                log_system_event(
                    f"[TencentCloud] 多 Flag 题 {code} 全部完成 "
                    f"({flag_got_count}/{flag_count}) 🎉"
                )
                return result

            # ── 还有剩余得分点，更新 ch_dict prompt 后继续 ──────────────
            remaining = flag_count - flag_got_count
            log_system_event(
                f"[TencentCloud] 多 Flag 题 {code}：已得 {flag_got_count}/{flag_count}，"
                f"继续寻找剩余 {remaining} 个得分点",
                {"flag_round": flag_round},
            )

            # 更新 _prompt 里的进度数字，让下一轮 PromptCompiler 拿到正确进度
            existing_prompt = ch_dict.get("_prompt", "")
            updated_prompt = re.sub(
                r"本题得分点进度[：:]\s*\d+\s*/\s*\d+",
                f"本题得分点进度: {flag_got_count}/{flag_count}",
                existing_prompt,
            )
            ch_dict["_prompt"] = updated_prompt

            # 重置 attempt 计数，给下一个得分点完整的重试预算
            attempt = 0
            attempt_history = []

    def _filter_and_prioritize(self, challenges: list[dict]) -> list[dict]:
        """过滤 + 按关卡、失败次数和难度排序

        排序策略:
        0. 若指定了 priority_level，level >= priority_level 的题目排最前
        1. 从未尝试过的题优先于已失败过的题
        2. 同等失败次数下，优先当前关卡（current_level）
        3. 其余关卡按 level 降序
        4. 同关卡内按难度: easy > medium > hard（比赛先拿分）
        5. 同难度内优先剩余可得分高者
        6. 剩余可得分相同时按题目总分降序
        """
        pending = [
            c for c in challenges
            if not c.get("solved")
            and (
                # priority_level 关卡（含更高关卡）的题不受 abandoned 过滤，始终保留
                (self._priority_level and int(c.get("level", 0) or 0) >= self._priority_level)
                or str(c.get("code") or c.get("id", "")) not in self._abandoned_codes
            )
        ]

        if self._category_filter:
            cat_lower = self._category_filter.lower()
            pending = [
                c for c in pending
                if self._get_category(c) == cat_lower
            ]

        difficulty_order = {"easy": 0, "medium": 1, "hard": 2}

        def sort_key(c):
            code = str(c.get("code") or c.get("id", ""))
            attempts = self._attempt_counts.get(code, 0)
            level = int(c.get("level", 999) or 999)
            # priority_level 及以上关卡排最前（0），其余为 1
            priority = 0 if (self._priority_level and level >= self._priority_level) else 1
            current_level_priority = 0 if level == int(self._current_level or 0) else 1
            remaining_score = int(
                c.get(
                    "remaining_score",
                    (c.get("points", 0) or 0) - (c.get("total_got_score", 0) or 0),
                ) or 0
            )
            return (
                priority,
                attempts,
                current_level_priority,
                -level,
                difficulty_order.get(c.get("difficulty", ""), 99),
                -remaining_score,
                -(c.get("points", 0) or 0),
            )

        pending.sort(key=sort_key)
        return pending

    def _build_challenge_dict(
        self, challenge: dict, target_url: Optional[str], work_dir,
    ) -> dict:
        """构建 challenge dict，增加腾讯云特有字段"""
        ch_dict = super()._build_challenge_dict(challenge, target_url, work_dir)

        # 注入平台特有信息
        ch_dict["_platform"] = "tencent_cloud"
        ch_dict["_flag_count"] = challenge.get("flag_count", 1)
        ch_dict["_flag_got_count"] = challenge.get("flag_got_count", 0)
        ch_dict["_total_score"] = challenge.get("total_score", challenge.get("points", 0))
        ch_dict["_total_got_score"] = challenge.get("total_got_score", 0)
        ch_dict["_remaining_score"] = challenge.get(
            "remaining_score",
            (challenge.get("points", 0) or 0) - (challenge.get("total_got_score", 0) or 0),
        )
        ch_dict["_level"] = challenge.get("level", 1)
        ch_dict["_current_level"] = self._current_level

        # 不锁死为 ctf-web，让后续分类预判仍有机会修正为 cloud / 其他类型。
        ch_dict["_mode"] = "ctf"

        # 如果有多个入口地址，全部记录
        entrypoint = challenge.get("entrypoint")
        if entrypoint and len(entrypoint) > 1:
            ch_dict["_target_urls"] = [
                self._entrypoint_to_url(ep) for ep in entrypoint
            ]

        flag_total = int(challenge.get("flag_count", 1) or 1)
        flag_got = int(challenge.get("flag_got_count", 0) or 0)
        score_total = int(challenge.get("total_score", challenge.get("points", 0)) or 0)
        score_got = int(challenge.get("total_got_score", 0) or 0)
        challenge_level = int(challenge.get("level", 1) or 1)
        effective_level = max(int(self._current_level or 1), challenge_level)

        prompt_lines = [
            f"当前已解锁关卡: {self._current_level}",
            f"本题所属关卡: {challenge_level}",
            f"本题得分点进度: {flag_got}/{flag_total}",
        ]
        if score_total > 0:
            prompt_lines.append(f"本题得分进度: {score_got}/{score_total}")
        if flag_total > 1 and flag_got < flag_total:
            prompt_lines.append(
                "注意：这是多阶段 Flag 题。拿到一个 Flag 不代表本题完成，"
                "必须继续寻找剩余得分点，直到平台显示该题已完成。"
            )
        if effective_level >= 3:
            prompt_lines.append(
                "注意：当前已进入多层网络/后渗透阶段。拿到 shell、凭据、路由、第二跳线索后，"
                "不要停在单点利用，优先继续提权、横向移动、内网枚举，并考虑使用 C2 agent。"
            )

        existing_prompt = ch_dict.get("_prompt", "").strip()
        extra_prompt = "\n".join(prompt_lines).strip()
        ch_dict["_prompt"] = (
            f"{existing_prompt}\n{extra_prompt}".strip()
            if existing_prompt else extra_prompt
        )

        return ch_dict

    # ==================== 辅助方法 ====================

    @staticmethod
    def _entrypoint_to_url(entrypoint: str) -> str:
        """将入口地址转为 URL（如果不含协议则加 http://）"""
        ep = entrypoint.strip()
        if not ep.startswith(("http://", "https://")):
            ep = f"http://{ep}"
        return ep

    async def _release_one_instance(self, exclude_code: str) -> bool:
        """释放一个实例（优先释放已解出的赛题实例）"""
        for code, meta in self._challenge_meta.items():
            if code == exclude_code:
                continue
            if meta.get("instance_status") != "running":
                continue

            # 优先释放已完成的题
            is_done = (
                meta.get("flag_count", 0) > 0
                and meta.get("flag_got_count", 0) >= meta.get("flag_count", 0)
            )
            if is_done:
                try:
                    await self._request(
                        "POST", "/stop_challenge", {"code": code},
                    )
                    log_system_event(
                        f"[TencentCloud] 释放已完成实例: {code}"
                    )
                    meta["instance_status"] = "stopped"
                    return True
                except Exception:
                    pass

        # 如果没有已完成的，释放任意一个
        for code, meta in self._challenge_meta.items():
            if code == exclude_code:
                continue
            if meta.get("instance_status") != "running":
                continue
            try:
                await self._request(
                    "POST", "/stop_challenge", {"code": code},
                )
                log_system_event(
                    f"[TencentCloud] 释放实例: {code}"
                )
                meta["instance_status"] = "stopped"
                return True
            except Exception:
                pass

        return False

    async def refresh_challenges(self) -> list[dict]:
        """刷新赛题列表（在解锁新关卡后调用）

        Returns:
            新发现的待做题目列表
        """
        new_challenges = await self.discover_challenges()
        pending = self._filter_and_prioritize(new_challenges)
        if pending:
            log_system_event(
                f"[TencentCloud] 刷新后发现 {len(pending)} 道待做题目"
            )
        return pending

    async def _poll_for_next_level_if_needed(self) -> list[dict]:
        """当前无待做题时，延时轮询几次看下一关是否已解锁。"""
        for attempt in range(1, self._unlock_poll_attempts + 1):
            log_system_event(
                f"[TencentCloud] 当前无待做题，等待下一关同步 ({attempt}/{self._unlock_poll_attempts})...",
                {
                    "current_level": self._current_level,
                    "sleep_seconds": self._unlock_poll_interval_seconds,
                },
            )
            await asyncio.sleep(self._unlock_poll_interval_seconds)

            challenges = await self.discover_challenges()
            self._total = len(self._seen_challenge_codes)
            self._solved = sum(1 for ch in challenges if ch.get("solved"))
            pending = self._filter_and_prioritize(challenges)
            if pending:
                log_system_event(
                    f"[TencentCloud] 轮询发现新待做题目: {len(pending)} 道",
                    {"current_level": self._current_level},
                )
                return pending

        return []

    async def run(self):
        """动态补位调度：谁结束就立刻补一个新题，并持续感知关卡解锁。"""
        try:
            inflight: dict[str, asyncio.Task] = {}
            retry_after: dict[str, float] = {}
            last_snapshot: dict[str, Any] | None = None

            while True:
                challenges = await self.discover_challenges()
                self._total = len(self._seen_challenge_codes)
                self._solved = sum(1 for ch in challenges if ch.get("solved"))

                if not challenges:
                    if inflight:
                        done, _ = await asyncio.wait(
                            inflight.values(),
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        for code, task in list(inflight.items()):
                            if task in done:
                                try:
                                    task.result()
                                except Exception as e:
                                    log_system_event(
                                        f"[TencentCloud] 并发任务异常 ({code}): {e}",
                                        level=logging.ERROR,
                                    )
                                retry_after[code] = time.monotonic() + self._retry_cooldown_seconds
                                inflight.pop(code, None)
                        continue
                    log_system_event("[TencentCloud] 无可用题目")
                    return

                snapshot = self._build_platform_snapshot(challenges)
                if last_snapshot is None or self._has_platform_progress(last_snapshot, snapshot):
                    retry_after.clear()
                last_snapshot = snapshot

                remaining_unsolved = [c for c in challenges if not c.get("solved")]
                pending = self._filter_and_prioritize(challenges)

                # 动态补位：始终尝试把空闲槽位补满
                scheduled = 0
                now = time.monotonic()
                for ch in pending:
                    if len(inflight) >= self._concurrency:
                        break
                    code = str(ch.get("code") or ch.get("id", ""))
                    if not code:
                        continue
                    if code in inflight:
                        continue
                    if retry_after.get(code, 0.0) > now:
                        continue
                    self._attempt_counts[code] = self._attempt_counts.get(code, 0) + 1
                    inflight[code] = asyncio.create_task(self._solve_one(ch))
                    scheduled += 1

                if scheduled:
                    log_system_event(
                        f"[TencentCloud] 动态补位: 新启动 {scheduled} 题, 运行中 {len(inflight)}/{self._concurrency}",
                        {"pending_count": len(pending)},
                    )

                if inflight:
                    done, _ = await asyncio.wait(
                        inflight.values(),
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for code, task in list(inflight.items()):
                        if task in done:
                            try:
                                task.result()
                            except Exception as e:
                                log_system_event(
                                    f"[TencentCloud] 并发任务异常 ({code}): {e}",
                                    level=logging.ERROR,
                                )
                            retry_after[code] = time.monotonic() + self._retry_cooldown_seconds
                            inflight.pop(code, None)
                    continue

                # 走到这里说明当前没有运行中的任务
                if not pending:
                    if remaining_unsolved:
                        log_system_event(
                            "[TencentCloud] 剩余未完成题目均已在本轮放弃，停止继续调度。",
                            {"abandoned_codes": sorted(self._abandoned_codes)},
                            level=logging.WARNING,
                        )
                    else:
                        polled_pending = await self._poll_for_next_level_if_needed()
                        if polled_pending:
                            continue
                        log_system_event("[TencentCloud] 所有题目已完成 🎉")
                    break

                # 仍有待做题，但当前都处于短冷却或等待平台状态刷新，先短等再继续
                log_system_event(
                    "[TencentCloud] 当前待做题均处于短冷却或等待平台状态刷新，稍后继续。",
                    {
                        "current_level": self._current_level,
                        "pending_count": len(pending),
                        "cooldown_count": sum(1 for t in retry_after.values() if t > time.monotonic()),
                    },
                    level=logging.WARNING,
                )
                await asyncio.sleep(5)
        finally:
            await self._close_http_client()

        self._print_summary()
