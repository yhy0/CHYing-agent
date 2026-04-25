"""xbow Benchmark Runner — 独立启动入口

对接 xbow-benchmark-agent API，全自动做题并记录基准测试结果。

用法:
  # 全部 104 题
  python run_benchmark.py

  # 指定题号
  python run_benchmark.py --benchmarks 1,2,3

  # 范围
  python run_benchmark.py --range 1-20

  # 并发 + 重试
  python run_benchmark.py -c 2 -r 6

  # 断点续做 / 重试失败
  python run_benchmark.py --resume
  python run_benchmark.py --retry-errors

  # 按难度/标签过滤
  python run_benchmark.py --level 1 --benchmark-meta-folder ./benchmarks

  # 指定 agent 名称（用于 dashboard 区分不同版本）
  python run_benchmark.py --agent-name chying-agent-v5 --benchmarks 22,27,29

环境变量:
  COMPETITION_BASE_URL   API 服务器地址（必填，或用 --api-url 指定）
  COMPETITION_API_TOKEN  认证 Token（必填，或用 --api-token 指定）
  MAX_RETRIES            最大重试次数（默认 4）
  SINGLE_TASK_TIMEOUT    单题超时（秒，默认在 .env 中配置）
  LLM_MODEL / LLM_API_KEY / LLM_BASE_URL  LLM 配置
"""

import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from chying_agent.observability import init_observability, shutdown_observability
init_observability()

from chying_agent.common import log_system_event
from chying_agent.db import init_db
from chying_agent.preflight import run_preflight_checks


def main():
    parser = argparse.ArgumentParser(
        description="xbow Benchmark Runner — 全自动做题 + 基准测试",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python run_benchmark.py --benchmarks 1,2,3
  python run_benchmark.py --range 1-20 -c 2
  python run_benchmark.py --resume
  python run_benchmark.py --retry-errors
  python run_benchmark.py --level 1 --benchmark-meta-folder ./benchmarks
  python run_benchmark.py --agent-name chying-v5 --benchmarks 22,27,29
        """,
    )

    parser.add_argument(
        "--api-url", type=str, default=None,
        help="API 服务器地址 (也可设 COMPETITION_BASE_URL 环境变量)",
    )
    parser.add_argument(
        "--api-token", type=str, default=None,
        help="认证 Token (也可设 COMPETITION_API_TOKEN 环境变量)",
    )
    parser.add_argument(
        "--benchmarks", type=str, default=None,
        help="逗号分隔的题号 (如 1,2,3)",
    )
    parser.add_argument(
        "--range", type=str, default=None,
        help="题号范围 (如 1-20)",
    )
    parser.add_argument(
        "--level", type=int, choices=[1, 2, 3], default=None,
        help="按难度过滤 (需配合 --benchmark-meta-folder)",
    )
    parser.add_argument(
        "--tag", type=str, default=None,
        help="按标签过滤 (如 sqli, 需配合 --benchmark-meta-folder)",
    )
    parser.add_argument(
        "--benchmark-meta-folder", type=str, default=None,
        help="benchmark 元数据目录 (XBEN-NNN-24/ 结构)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="断点续做（跳过已完成的题目）",
    )
    parser.add_argument(
        "--retry-errors", action="store_true",
        help="只重做 ERROR/TIMEOUT 的题目",
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=1,
        help="并发做题数 (默认 1)",
    )
    parser.add_argument(
        "-r", "--max-retries", type=int, default=None,
        help="每道题最大重试次数 (默认从 MAX_RETRIES 环境变量读取，兜底 4)",
    )
    parser.add_argument(
        "--agent-name", type=str, default="default",
        help="Agent 名称（用于 dashboard 追踪）",
    )
    parser.add_argument(
        "--skip-preflight", action="store_true",
        help="跳过启动检查",
    )

    args = parser.parse_args()

    # ---- 解析必填参数 ----
    api_url = args.api_url or os.getenv("COMPETITION_BASE_URL")
    if not api_url:
        parser.error(
            "缺少 API 地址: 请通过 --api-url 参数或 COMPETITION_BASE_URL 环境变量指定"
        )

    api_token = args.api_token or os.getenv("COMPETITION_API_TOKEN")
    if not api_token:
        parser.error(
            "缺少认证 Token: 请通过 --api-token 参数或 COMPETITION_API_TOKEN 环境变量指定"
        )

    max_retries = args.max_retries or int(os.getenv("MAX_RETRIES", "4"))

    # ---- 解析题号 ----
    benchmark_nums: list[int] = []

    if args.benchmarks:
        benchmark_nums = [int(x.strip()) for x in args.benchmarks.split(",")]
    elif args.range:
        m = re.match(r"(\d+)-(\d+)", args.range)
        if not m:
            parser.error(f"无效的范围格式: {args.range} (应为 N-M)")
        benchmark_nums = list(range(int(m.group(1)), int(m.group(2)) + 1))
    else:
        # 默认：全部 104 题
        benchmark_nums = list(range(1, 105))

    # ---- 元数据过滤 ----
    if args.level or args.tag:
        if not args.benchmark_meta_folder:
            parser.error("--level/--tag 需要配合 --benchmark-meta-folder 使用")

        from chying_agent.contest.benchmark_runner import load_benchmark_meta
        meta = load_benchmark_meta(Path(args.benchmark_meta_folder))

        if args.level:
            benchmark_nums = [
                n for n in benchmark_nums
                if meta.get(n, {}).get("level") == args.level
            ]
        if args.tag:
            benchmark_nums = [
                n for n in benchmark_nums
                if args.tag in meta.get(n, {}).get("tags", [])
            ]

    if not benchmark_nums:
        print("没有匹配的 benchmark")
        sys.exit(1)

    # ---- 启动前检查 ----
    if not args.skip_preflight:
        if not run_preflight_checks():
            return

    init_db()

    # ---- 打印配置 ----
    display_nums = str(benchmark_nums[:10])
    if len(benchmark_nums) > 10:
        display_nums += f"... (共 {len(benchmark_nums)} 道)"

    log_system_event("=" * 60)
    log_system_event("🔬 xbow Benchmark Runner")
    log_system_event("=" * 60)
    log_system_event(f"  API 地址:    {api_url}")
    log_system_event(f"  Token:       {api_token[:8]}...{api_token[-4:]}" if len(api_token) > 12 else f"  Token:       {api_token}")
    log_system_event(f"  Agent:       {args.agent_name}")
    log_system_event(f"  题目:        {display_nums}")
    log_system_event(f"  并发数:      {args.concurrency}")
    log_system_event(f"  最大重试:    {max_retries}")
    log_system_event(f"  单题超时:    {os.getenv('SINGLE_TASK_TIMEOUT', 'not set')}s")
    if args.resume:
        log_system_event(f"  模式:        断点续做")
    elif args.retry_errors:
        log_system_event(f"  模式:        重试失败")
    log_system_event("=" * 60)

    # ---- 启动 Runner ----
    asyncio.run(
        _run(
            api_url=api_url,
            api_token=api_token,
            benchmark_nums=benchmark_nums,
            agent_name=args.agent_name,
            concurrency=args.concurrency,
            max_retries=max_retries,
            resume=args.resume,
            retry_errors=args.retry_errors,
        )
    )


async def _run(
    *,
    api_url: str,
    api_token: str,
    benchmark_nums: list[int],
    agent_name: str,
    concurrency: int,
    max_retries: int,
    resume: bool,
    retry_errors: bool,
):
    from chying_agent.contest.benchmark_runner import BenchmarkCTFRunner

    runner = BenchmarkCTFRunner(
        api_url=api_url,
        api_token=api_token,
        benchmark_nums=benchmark_nums,
        agent_name=agent_name,
        concurrency=concurrency,
        max_retries=max_retries,
        resume=resume,
        retry_errors=retry_errors,
    )
    await runner.run()


if __name__ == "__main__":
    main()
    shutdown_observability()
    os._exit(0)
