"""HackTheBox CTF 比赛 — 独立启动入口

通过 MCP 协议对接 HTB 平台，全自动完成：发现比赛 → 加入 → 做题 → 提交 Flag。

用法:
  # 从环境变量读取配置
  python run_htb_ctf.py

  # 命令行指定参数
  python run_htb_ctf.py --server http://HOST/mcp --token YOUR_TOKEN

  # 指定比赛 ID + 分类过滤
  python run_htb_ctf.py --ctf-id 123 --category web

  # 调整并发和重试
  python run_htb_ctf.py -c 2 -r 6

环境变量:
  MCP_CTF_SERVER   MCP 比赛服务器 URL（必填，或用 --server 指定）
  AGENT_TOKEN      队伍认证 Token（必填，或用 --token 指定）
  MAX_RETRIES      最大重试次数（默认 4）
  LLM_MODEL        LLM 模型名称
  LLM_API_KEY      LLM API Key
  LLM_BASE_URL     LLM API Base URL
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
        description="HackTheBox CTF — MCP 协议全自动做题",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python run_htb_ctf.py
  python run_htb_ctf.py --server http://host/mcp --token abc123
  python run_htb_ctf.py --ctf-id 42 --category web -c 2
        """,
    )

    parser.add_argument(
        "--server", type=str, default=None,
        help="MCP 比赛服务器 URL (也可设 MCP_CTF_SERVER 环境变量)",
    )
    parser.add_argument(
        "--token", type=str, default=None,
        help="队伍认证 Token (也可设 AGENT_TOKEN 环境变量)",
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=3,
        help="并发做题数 (默认 3)",
    )
    parser.add_argument(
        "-r", "--max-retries", type=int, default=None,
        help="每道题最大重试次数 (默认从 MAX_RETRIES 环境变量读取，兜底 4)",
    )
    parser.add_argument(
        "--ctf-id", type=int, default=None,
        help="指定比赛 ID（跳过自动选择）",
    )
    parser.add_argument(
        "--category", type=str, default=None,
        help="只做指定分类的题目 (如 web)",
    )
    parser.add_argument(
        "--skip-preflight", action="store_true",
        help="跳过启动检查",
    )

    args = parser.parse_args()

    # ---- 解析必填参数 ----
    server_url = args.server or os.getenv("MCP_CTF_SERVER")
    if not server_url:
        parser.error(
            "缺少 MCP 服务器地址: 请通过 --server 参数或 MCP_CTF_SERVER 环境变量指定"
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
    log_system_event("🏴‍☠️ HackTheBox CTF")
    log_system_event("=" * 60)
    log_system_event(f"  MCP 服务器:  {server_url}")
    log_system_event(f"  Token:       {agent_token[:8]}...{agent_token[-4:]}")
    log_system_event(f"  并发数:      {args.concurrency}")
    log_system_event(f"  最大重试:    {max_retries}")
    if args.ctf_id:
        log_system_event(f"  比赛 ID:     {args.ctf_id}")
    if args.category:
        log_system_event(f"  分类过滤:    {args.category}")
    log_system_event("=" * 60)

    # ---- 启动 Runner ----
    asyncio.run(
        run(
            server_url=server_url,
            agent_token=agent_token,
            concurrency=args.concurrency,
            max_retries=max_retries,
            category_filter=args.category,
            ctf_id=args.ctf_id,
        )
    )


async def run(
    server_url: str,
    agent_token: str,
    concurrency: int = 3,
    max_retries: int = 4,
    category_filter: str | None = None,
    ctf_id: int | None = None,
):
    from chying_agent.contest.htb_runner import HTBCTFRunner

    runner = HTBCTFRunner(
        server_url=server_url,
        agent_token=agent_token,
        concurrency=concurrency,
        max_retries=max_retries,
        category_filter=category_filter,
        ctf_id=ctf_id,
    )
    await runner.run()


if __name__ == "__main__":
    main()
    shutdown_observability()
    os._exit(0)
