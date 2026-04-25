"""第二届腾讯云黑客松智能渗透挑战赛 — 独立启动入口

启动后全自动完成：拉取赛题 → 启动实例 → 渗透做题 → 提交 Flag → 过关继续。

用法:
  # 基本启动（从环境变量读取配置）
  python run_tencent_ctf.py

  # 命令行指定参数
  python run_tencent_ctf.py --server 1.2.3.4:8080 --token YOUR_TOKEN

  # 调整并发和重试
  python run_tencent_ctf.py -c 2 -r 6

环境变量:
  SERVER_HOST    平台服务器地址（必填，或用 --server 指定）
  AGENT_TOKEN    队伍认证 Token（必填，或用 --token 指定）
  MAX_RETRIES    最大重试次数（默认 4）
  LLM_MODEL      LLM 模型名称
  LLM_API_KEY    LLM API Key
  LLM_BASE_URL   LLM API Base URL
"""

import argparse
import asyncio
import os

from dotenv import load_dotenv
load_dotenv()

from chying_agent.observability import init_observability, shutdown_observability
init_observability()

from chying_agent.common import log_system_event
from chying_agent.db import init_db
from chying_agent.preflight import run_preflight_checks


def main():
    parser = argparse.ArgumentParser(
        description="腾讯云黑客松智能渗透挑战赛 — 全自动做题",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python run_tencent_ctf.py
  python run_tencent_ctf.py --server 1.2.3.4:8080 --token abc123
  python run_tencent_ctf.py -c 2 -r 6
  python run_tencent_ctf.py --category web
        """,
    )

    parser.add_argument(
        "--server", type=str, default=None,
        help="平台服务器地址 (也可设 SERVER_HOST 环境变量)",
    )
    parser.add_argument(
        "--token", type=str, default=None,
        help="队伍认证 Token (也可设 AGENT_TOKEN 环境变量)",
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=3,
        help="并发做题数 (默认 3，平台上限也是 3)",
    )
    parser.add_argument(
        "-r", "--max-retries", type=int, default=None,
        help="每道题最大重试次数 (默认从 MAX_RETRIES 环境变量读取，兜底 4)",
    )
    parser.add_argument(
        "--category", type=str, default=None,
        help="只做指定分类的题目 (如 web)",
    )
    parser.add_argument(
        "--priority-level", type=int, default=None,
        help="优先做 >= 指定关卡的题目 (如 3 表示优先做关卡三及以上)",
    )
    parser.add_argument(
        "--skip-preflight", action="store_true",
        help="跳过启动检查",
    )

    args = parser.parse_args()

    # ---- 解析必填参数 ----
    server_host = args.server or os.getenv("SERVER_HOST")
    if not server_host:
        parser.error(
            "缺少平台地址: 请通过 --server 参数或 SERVER_HOST 环境变量指定"
        )

    agent_token = args.token or os.getenv("AGENT_TOKEN")
    if not agent_token:
        parser.error(
            "缺少认证 Token: 请通过 --token 参数或 AGENT_TOKEN 环境变量指定"
        )

    max_retries = args.max_retries or int(os.getenv("MAX_RETRIES", "4"))

    # ---- 启动前检查 ----
    if not args.skip_preflight:
        if not run_preflight_checks():
            return

    init_db()

    # ---- 打印配置 ----
    log_system_event("=" * 60)
    log_system_event("🏆 第二届腾讯云黑客松智能渗透挑战赛")
    log_system_event("=" * 60)
    log_system_event(f"  平台地址:   {server_host}")
    log_system_event(f"  Token:      {agent_token[:8]}...{agent_token[-4:]}")
    log_system_event(f"  并发数:     {args.concurrency}")
    log_system_event(f"  最大重试:   {max_retries}")
    log_system_event("  使用提示:   是（固定开启）")
    if args.category:
        log_system_event(f"  分类过滤:   {args.category}")
    if args.priority_level:
        log_system_event(f"  优先关卡:   >= {args.priority_level}")
    log_system_event("=" * 60)

    # ---- 启动 Runner ----
    asyncio.run(
        run(
            server_host=server_host,
            agent_token=agent_token,
            concurrency=args.concurrency,
            max_retries=max_retries,
            use_hints=True,
            category_filter=args.category,
            priority_level=args.priority_level,
        )
    )


async def run(
    server_host: str,
    agent_token: str,
    concurrency: int = 3,
    max_retries: int = 4,
    use_hints: bool = True,
    category_filter: str | None = None,
    priority_level: int | None = None,
):
    from chying_agent.contest.tencent_cloud_runner import TencentCloudCTFRunner

    runner = TencentCloudCTFRunner(
        server_host=server_host,
        agent_token=agent_token,
        concurrency=concurrency,
        max_retries=max_retries,
        use_hints=use_hints,
        category_filter=category_filter,
        priority_level=priority_level,
    )
    await runner.run()


if __name__ == "__main__":
    main()
    shutdown_observability()
    os._exit(0)
