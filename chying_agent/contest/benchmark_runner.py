"""xbow-benchmark-agent 适配器 — BenchmarkCTFRunner

对接 xbow-benchmark-agent 的 HTTP API，将基准测试流程映射到
BaseCTFRunner 的模板方法，复用重试、hint 注入、多来源 flag 收集等能力。

API 接口:
  POST /api/v1/admin/start  → 按 benchmark_ids 启动容器
  POST /api/v1/admin/stop   → 停止容器
  GET  /api/v1/hint/{code}  → 获取题目描述/提示
  POST /api/v1/answer       → 提交 flag
  POST /api/v1/runs/start   → Dashboard 记录开始 (可选)
  POST /api/v1/runs/finish  → Dashboard 记录结束 (可选)

认证方式: Authorization: Bearer <token>
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import httpx

from ..common import log_system_event
from .base import BaseCTFRunner


# ==================== Data Models ====================


@dataclass
class BenchmarkResult:
    """单题基准测试结果"""
    benchmark_num: int
    benchmark_id: str       # XBEN-NNN-24
    challenge_code: str     # UUID from API (runtime)
    status: str             # SUCCESS / FAILURE / TIMEOUT / ERROR
    success: bool
    found_flag: str | None
    duration_seconds: float
    cost_usd: float
    error_message: str | None
    start_time: str
    end_time: str
    target_url: str = ""
    description: str = ""


# ==================== Async API Client ====================


class BenchmarkAPIClient:
    """xbow-benchmark-agent API 异步客户端"""

    def __init__(self, base_url: str, token: str):
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(360, connect=30),
        )

    async def close(self):
        await self._client.aclose()

    async def _request(self, method: str, path: str, json_data: dict | None = None) -> Any:
        resp = await self._client.request(method, path, json=json_data)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"API {method} {path}: HTTP {resp.status_code} — {resp.text[:500]}"
            )
        return resp.json()

    # ---- 核心接口 ----

    async def admin_start(self, benchmark_ids: list[int]) -> list[dict]:
        resp = await self._request("POST", "/api/v1/admin/start", {"benchmark_ids": benchmark_ids})
        return resp.get("started", [])

    async def admin_stop(self, challenge_code: str) -> None:
        await self._request("POST", "/api/v1/admin/stop", {"challenge_code": challenge_code})

    async def get_hint(self, challenge_code: str) -> str:
        resp = await self._request("GET", f"/api/v1/hint/{challenge_code}")
        if isinstance(resp, str):
            return resp
        return resp.get("hint_content", resp.get("hint", resp.get("description", "")))

    async def submit_answer(
        self, challenge_code: str, flag: str, agent_name: str | None = None,
    ) -> dict:
        data: dict[str, str] = {"challenge_code": challenge_code, "answer": flag}
        if agent_name:
            data["agent_name"] = agent_name
        return await self._request("POST", "/api/v1/answer", data)

    # ---- Dashboard 埋点（fire-and-forget） ----

    async def run_start(self, **kwargs) -> dict:
        try:
            return await self._request("POST", "/api/v1/runs/start", kwargs)
        except Exception as e:
            log_system_event(f"[Benchmark] run_start 埋点失败: {e}", level=logging.WARNING)
            return {}

    async def run_finish(self, **kwargs) -> dict:
        try:
            return await self._request("POST", "/api/v1/runs/finish", kwargs)
        except Exception as e:
            log_system_event(f"[Benchmark] run_finish 埋点失败: {e}", level=logging.WARNING)
            return {}


# ==================== Benchmark Metadata ====================


def load_benchmark_meta(folder: Path) -> dict[int, dict]:
    """从 XBEN-NNN-24/benchmark.json 加载元数据。

    Returns:
        {benchmark_num: {"level": int, "tags": [str], ...}}
    """
    meta: dict[int, dict] = {}
    if not folder.exists():
        return meta
    for subdir in sorted(folder.iterdir()):
        if not subdir.is_dir():
            continue
        m = re.match(r"XBEN-(\d+)-24", subdir.name)
        if not m:
            continue
        bm_file = subdir / "benchmark.json"
        if bm_file.exists():
            try:
                meta[int(m.group(1))] = json.loads(bm_file.read_text())
            except Exception:
                pass
    return meta


# ==================== State Management ====================


def _load_state(state_file: Path) -> dict[int, dict]:
    """从 state.json 加载已完成的结果"""
    if not state_file.exists():
        return {}
    try:
        data = json.loads(state_file.read_text())
        return {r["benchmark_num"]: r for r in data.get("results", [])}
    except Exception:
        return {}


def _save_state(state_file: Path, results: list[BenchmarkResult]):
    """保存结果到 state.json"""
    state_file.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "updated_at": datetime.now().isoformat(),
        "results": [asdict(r) for r in results],
    }
    state_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))


# ==================== Runner ====================


class BenchmarkCTFRunner(BaseCTFRunner):
    """xbow-benchmark-agent 适配器

    设计要点:
    - discover_challenges() 根据 benchmark_nums 生成 synthetic challenge dicts
    - start_challenge() 调 admin_start 启动容器，就地填充 _challenge_code + target_info
    - _should_skip() 实现 resume/retry-errors
    - _on_solve_start() 预取 hint、归档 work_dir、dashboard 埋点
    - _on_solve_finish() 记录 BenchmarkResult、保存 state、dashboard 埋点
    """

    def __init__(
        self,
        *,
        api_url: str,
        api_token: str,
        benchmark_nums: list[int],
        agent_name: str = "default",
        resume: bool = False,
        retry_errors: bool = False,
        output_dir: Path | None = None,
        **kwargs,
    ):
        super().__init__(work_dir_name="benchmark", **kwargs)

        self._api = BenchmarkAPIClient(api_url, api_token)
        self._benchmark_nums = benchmark_nums
        self._agent_name = agent_name

        self._output_dir = output_dir or Path("benchmark-results")
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._state_file = self._output_dir / "state.json"

        # Resume / retry-errors
        self._completed: dict[int, dict] = {}
        self._results: list[BenchmarkResult] = []
        self._results_lock = asyncio.Lock()
        self._consecutive_start_failures = 0
        self._run_start_time = datetime.now()

        if resume:
            self._completed = _load_state(self._state_file)
            self._results = [BenchmarkResult(**v) for v in self._completed.values()]
            if self._completed:
                log_system_event(
                    f"[Benchmark] 断点续做: 已有 {len(self._completed)} 道已完成"
                )
        elif retry_errors:
            prev = _load_state(self._state_file)
            for bnum, rdata in prev.items():
                if rdata.get("status") in ("ERROR", "TIMEOUT"):
                    pass  # 不加入 completed → 会被重试
                else:
                    self._completed[bnum] = rdata
                    self._results.append(BenchmarkResult(**rdata))
            retry_count = len(prev) - len(self._completed)
            log_system_event(
                f"[Benchmark] 重试失败题目: {retry_count} 道, "
                f"保留 {len(self._completed)} 道已成功"
            )

    # ==================== 子类实现 ====================

    async def discover_challenges(self) -> list[dict]:
        """根据 benchmark_nums 生成 synthetic challenge dicts

        这些只是占位符，真正的 challenge_code 和 target_info 在
        start_challenge() 调 admin_start 后才填充。
        """
        challenges = []
        for bnum in self._benchmark_nums:
            benchmark_id = f"XBEN-{bnum:03d}-24"
            challenges.append({
                "id": bnum,
                "code": benchmark_id,
                "name": benchmark_id,
                "category": "web",
                "difficulty": "unknown",
                "points": 0,
                "solved": bnum in self._completed,
                # 私有字段
                "_benchmark_num": bnum,
                "_benchmark_id": benchmark_id,
            })
        log_system_event(
            f"[Benchmark] 发现 {len(challenges)} 道题目, "
            f"待做 {sum(1 for c in challenges if not c['solved'])} 道"
        )
        return challenges

    async def start_challenge(self, challenge: dict) -> Optional[str]:
        """调 admin_start 启动容器，就地填充 challenge dict"""
        bnum = challenge["_benchmark_num"]
        benchmark_id = challenge["_benchmark_id"]

        try:
            started = await self._api.admin_start([bnum])
            if not started:
                raise RuntimeError("admin_start 返回空列表")

            ch = started[0]
            challenge_code = ch.get("challenge_code", "")
            target_info = ch.get("target_info", {})
            ip = target_info.get("ip", "")
            ports = target_info.get("port", target_info.get("ports", []))
            if isinstance(ports, list) and ports:
                port = ports[0]
            elif isinstance(ports, (int, str)):
                port = ports
            else:
                port = None

            target_url = f"http://{ip}:{port}" if port else f"http://{ip}"

            # 就地更新 challenge dict，下游所有方法都能看到
            challenge["_challenge_code"] = challenge_code
            challenge["_target_url"] = target_url
            challenge["_target_info"] = target_info

            self._consecutive_start_failures = 0
            log_system_event(
                f"[Benchmark] 容器启动: {benchmark_id} → "
                f"{challenge_code[:12]}... → {target_url}"
            )
            return target_url

        except Exception as e:
            # 连续超时指数退避
            if "timed out" in str(e).lower():
                self._consecutive_start_failures += 1
                if self._consecutive_start_failures >= 3:
                    wait = min(120, 30 * self._consecutive_start_failures)
                    log_system_event(
                        f"[Benchmark] 连续 {self._consecutive_start_failures} 次超时, "
                        f"等待 {wait}s...",
                        level=logging.WARNING,
                    )
                    await asyncio.sleep(wait)
            else:
                self._consecutive_start_failures = 0

            log_system_event(
                f"[Benchmark] 容器启动失败 ({benchmark_id}): {e}",
                level=logging.ERROR,
            )
            # 返回 None 让 solver 自然失败，_on_solve_finish 会记录 ERROR
            return None

    async def stop_challenge(self, challenge: dict) -> None:
        challenge_code = challenge.get("_challenge_code")
        if not challenge_code:
            return
        try:
            await self._api.admin_stop(challenge_code)
            log_system_event(f"[Benchmark] 容器已停止: {challenge_code[:12]}...")
        except Exception as e:
            log_system_event(
                f"[Benchmark] 容器停止失败: {e}", level=logging.WARNING,
            )

    async def submit_flag(self, challenge: dict, flag: str) -> bool:
        challenge_code = challenge.get("_challenge_code", "")
        if not challenge_code:
            return False
        try:
            resp = await self._api.submit_answer(
                challenge_code, flag, agent_name=self._agent_name,
            )
            correct = resp.get("correct", resp.get("success", resp.get("is_correct", False)))
            log_system_event(
                f"[Benchmark] submit({challenge.get('_benchmark_id', '')}): "
                f"{'✓ 正确' if correct else '✗ 错误'}"
            )
            return correct
        except Exception as e:
            log_system_event(f"[Benchmark] submit 失败: {e}", level=logging.WARNING)
            return False

    async def get_hint(self, challenge: dict) -> str:
        challenge_code = challenge.get("_challenge_code", "")
        if not challenge_code:
            return "容器未启动，无法获取提示"
        try:
            return await self._api.get_hint(challenge_code)
        except Exception as e:
            return f"获取提示失败: {e}"

    # ==================== Hook 覆盖 ====================

    async def _should_skip(self, challenge: dict) -> bool:
        bnum = challenge.get("_benchmark_num")
        return bnum in self._completed

    async def _on_solve_start(self, challenge: dict, target_url: Optional[str]) -> None:
        """预取 hint → 归档旧 work_dir → Dashboard 埋点"""
        challenge_code = challenge.get("_challenge_code", "")
        benchmark_id = challenge["_benchmark_id"]
        bnum = challenge["_benchmark_num"]

        # 预取 hint 作为 description
        if challenge_code:
            try:
                description = await self._api.get_hint(challenge_code)
                challenge["description"] = description
                if description:
                    log_system_event(f"[Benchmark] 描述: {description[:100]}...")
            except Exception:
                pass

        # 归档旧 work_dir 防止交叉污染
        self._archive_work_dir(challenge, benchmark_id)

        # Dashboard 埋点
        await self._api.run_start(
            agent_name=self._agent_name,
            benchmark_id=benchmark_id,
            benchmark_num=bnum,
            challenge_code=challenge_code,
            target_url=target_url,
        )

    async def _on_solve_finish(
        self, challenge: dict, result: Optional[dict], duration_seconds: float,
    ) -> None:
        """记录结果 + Dashboard 埋点 + 保存 state"""
        benchmark_id = challenge["_benchmark_id"]
        challenge_code = challenge.get("_challenge_code", "")
        bnum = challenge["_benchmark_num"]

        found_flag = result.get("flag") if result else None
        success = bool(result and result.get("success"))

        # 判定 status
        error = None
        if not result or not result.get("success"):
            # 检查是否有 error 信息
            if result:
                error = result.get("error")
            if not challenge_code:
                error = "容器启动失败"

        if error and "Timeout" in str(error):
            status = "TIMEOUT"
        elif error:
            status = "ERROR"
        elif success:
            status = "SUCCESS"
        else:
            status = "FAILURE"

        now = datetime.now()
        br = BenchmarkResult(
            benchmark_num=bnum,
            benchmark_id=benchmark_id,
            challenge_code=challenge_code,
            status=status,
            success=success,
            found_flag=found_flag,
            duration_seconds=round(duration_seconds, 1),
            cost_usd=0.0,  # TODO: 从 orchestrator 获取
            error_message=str(error) if error else None,
            start_time=now.isoformat(),
            end_time=now.isoformat(),
            target_url=challenge.get("_target_url", ""),
            description=challenge.get("description", "")[:200],
        )

        async with self._results_lock:
            self._results.append(br)
            self._completed[bnum] = asdict(br)
            _save_state(self._state_file, self._results)

        mark = "✓" if success else "✗"
        log_system_event(
            f"[Benchmark] [{mark}] {benchmark_id} | {status} | "
            f"{duration_seconds:.0f}s | flag={found_flag or 'N/A'}"
        )

        # Dashboard 埋点
        await self._api.run_finish(
            agent_name=self._agent_name,
            benchmark_id=benchmark_id,
            status=status.lower(),
            challenge_code=challenge_code,
            duration_seconds=round(duration_seconds, 1),
            cost_usd=0.0,
            found_flag=found_flag,
            error_message=str(error) if error else None,
        )

    # ==================== 覆盖基类方法 ====================

    def _build_challenge_dict(self, challenge: dict, target_url, work_dir) -> dict:
        ch_dict = super()._build_challenge_dict(challenge, target_url, work_dir)
        # 用 hint 获取的 description 覆盖 prompt
        desc = challenge.get("description", "")
        if desc:
            ch_dict["_prompt"] = desc
        ch_dict["_platform"] = "benchmark"
        return ch_dict

    async def run(self):
        """重写以添加最终报告和 API client 清理"""
        try:
            await super().run()
        finally:
            self._save_report()
            await self._api.close()

    def _print_summary(self):
        total_run = len(self._results)
        total_success = sum(1 for r in self._results if r.success)
        total_fail = sum(1 for r in self._results if r.status == "FAILURE")
        total_timeout = sum(1 for r in self._results if r.status == "TIMEOUT")
        total_error = sum(1 for r in self._results if r.status == "ERROR")
        total_cost = sum(r.cost_usd for r in self._results)
        total_duration = sum(r.duration_seconds for r in self._results)

        log_system_event("=" * 60)
        log_system_event("BENCHMARK COMPLETE")
        log_system_event(f"  Total:    {total_run}")
        if total_run:
            log_system_event(f"  Success:  {total_success} ({total_success / total_run * 100:.1f}%)")
        log_system_event(f"  Failure:  {total_fail}")
        log_system_event(f"  Timeout:  {total_timeout}")
        log_system_event(f"  Error:    {total_error}")
        log_system_event(f"  Duration: {total_duration:.0f}s ({total_duration / 60:.1f}min)")
        log_system_event(f"  Cost:     ${total_cost:.2f}")
        log_system_event("=" * 60)

    # ==================== 辅助方法 ====================

    def _archive_work_dir(self, challenge: dict, benchmark_id: str):
        """归档旧 work_dir 防止交叉污染"""
        ch_work_dir = self._setup_work_dir(challenge)
        if not ch_work_dir.exists():
            return
        try:
            if not any(ch_work_dir.iterdir()):
                return
        except Exception:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive = ch_work_dir.parent / f"{ch_work_dir.name}__{benchmark_id}__{timestamp}"
        try:
            ch_work_dir.rename(archive)
            log_system_event(f"[Benchmark] 归档 work_dir: {archive.name}")
        except Exception as e:
            log_system_event(f"[Benchmark] 归档失败: {e}", level=logging.WARNING)

    def _save_report(self):
        """保存最终 JSON 报告"""
        run_end = datetime.now()
        total_run = len(self._results)
        report = {
            "run_start": self._run_start_time.isoformat(),
            "run_end": run_end.isoformat(),
            "config": {
                "single_task_timeout": os.getenv("SINGLE_TASK_TIMEOUT", "not set"),
                "model": os.getenv("LLM_MODEL", "unknown"),
                "concurrency": self._concurrency,
                "agent_name": self._agent_name,
            },
            "summary": {
                "total": total_run,
                "success": sum(1 for r in self._results if r.success),
                "failure": sum(1 for r in self._results if r.status == "FAILURE"),
                "timeout": sum(1 for r in self._results if r.status == "TIMEOUT"),
                "error": sum(1 for r in self._results if r.status == "ERROR"),
                "success_rate": round(
                    sum(1 for r in self._results if r.success) / total_run * 100, 1
                ) if total_run else 0,
                "total_duration_seconds": round(
                    sum(r.duration_seconds for r in self._results), 1
                ),
                "total_cost_usd": round(sum(r.cost_usd for r in self._results), 2),
            },
            "results": [asdict(r) for r in self._results],
        }

        report_file = self._output_dir / f"report_{self._run_start_time.strftime('%Y%m%d_%H%M%S')}.json"
        report_file.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        log_system_event(f"[Benchmark] 报告已保存: {report_file}")
