"""CHYing Agent 主程序 - 支持多种运行模式

运行模式：
1. CTF 自动检测模式 (--ctf): 从 agent-work/ctf/ 目录自动加载题目
2. 单目标模式 (-t): 直接指定目标 URL 进行渗透测试
3. 多目标手动模式: 手动指定各类型题目路径

运行场景 (-m/--mode):
- ctf: CTF 通用模式，自动检测题目类型（web/pwn/misc/crypto）
- ctf-web: CTF Web 专用模式
- pentest: 渗透测试模式
"""

import argparse
import asyncio
import os
import logging
import re
from typing import Optional
from urllib.parse import urlparse

from dotenv import load_dotenv
load_dotenv()

from chying_agent.observability import init_observability, shutdown_observability
init_observability()

from chying_agent.runtime.singleton import get_config_manager
from chying_agent.task_manager import ChallengeStats
from chying_agent.common import log_system_event
from chying_agent.config import AVAILABLE_MODES
from chying_agent.db import init_db
from chying_agent.preflight import run_preflight_checks


# ==================== 配置 ====================
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "4"))


def _url_to_challenge_code(url: str) -> str:
    """将完整 URL 转换为安全的 challenge_code

    保留 scheme、host、port、path 信息，确保不同路径的 URL 生成不同的 code。
    例如:
    - https://example.com/challenge/1 -> manual_example.com_443_challenge_1
    - https://example.com/challenge/2 -> manual_example.com_443_challenge_2
    - http://10.0.0.1:8080           -> manual_10.0.0.1_8080
    """
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 基础部分: host_port
    parts = [host, str(port)]

    # 添加路径部分（去掉前后斜杠，替换 / 为 _）
    path = parsed.path.strip("/")
    if path:
        parts.append(path.replace("/", "_"))

    # 添加 query 参数（如果有）
    if parsed.query:
        parts.append(parsed.query)

    raw = "_".join(parts)
    # 替换不安全字符为下划线，合并连续下划线
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', raw)
    safe = re.sub(r'_+', '_', safe)
    safe = safe.strip('_')

    return f"manual_{safe}"


def parse_target_urls(target_str: str, mode: str = "ctf") -> dict:
    """解析一个或多个 URL（逗号分隔），构造虚拟 challenge 对象

    支持格式：
    - http://192.168.1.100:8080
    - https://example.com
    - 192.168.1.100:8080 (默认 http)
    - 192.168.1.100 (默认端口 80)
    - http://web:8080,http://api:3000 (逗号分隔，同一题目多个 URL)
    - https://example.com/challenge/2 (路径会纳入 challenge_code)

    注意: 不支持 CIDR 网段格式（如 192.168.1.0/24）
    """
    urls = [u.strip() for u in target_str.split(",") if u.strip()]
    if not urls:
        raise ValueError(f"无效的目标字符串（为空）: {target_str!r}")

    parsed_targets = []
    all_hosts = []
    all_ports = []
    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        parsed = urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        parsed_targets.append(url)
        all_hosts.append(host)
        all_ports.append(port)

    primary_host = all_hosts[0]
    primary_port = all_ports[0]
    # 基于完整 URL 生成 challenge_code，保留路径信息
    challenge_code = _url_to_challenge_code(parsed_targets[0])

    return {
        "challenge_code": challenge_code,
        # URL 目标先标记为 unknown，后续在运行前再做预分类。
        "category": "unknown",
        "difficulty": "unknown",
        "points": 0,
        "target_info": {
            "ip": primary_host,
            "port": list(set(all_ports)),
            "urls": parsed_targets,
        },
        "_target_url": parsed_targets[0],
        "_target_urls": parsed_targets,
        "_mode": mode,
    }


async def run_targets(targets: list[str], max_retries: int = 0, mode: str = "ctf", prompt: str = ""):
    """目标模式：支持多个 -t 参数，每个 -t 可包含逗号分隔的多 URL（同一题目）"""
    from chying_agent.challenge_solver import solve_single_challenge, normalize_challenge_category

    # 配置验证
    try:
        config = get_config_manager().config
    except Exception as e:
        log_system_event(f"❌ 配置加载失败: {e}", level=logging.ERROR)
        raise

    stats = ChallengeStats()
    concurrent_semaphore = asyncio.Semaphore(1)

    for target_str in targets:
        challenge = parse_target_urls(target_str, mode=mode)
        if prompt:
            challenge["_prompt"] = prompt
        normalize_challenge_category(challenge, allow_probe=False, fallback_to_web=False)
        target_urls = challenge.get("_target_urls", [])
        display_label = ", ".join(target_urls) if len(target_urls) > 1 else target_urls[0]

        log_system_event("=" * 60)
        log_system_event(f"🎯 目标模式: {display_label}")
        log_system_event("=" * 60)

        attempt = 0
        result = None
        attempt_history = []

        try:
            while attempt <= max_retries:
                if attempt > 0:
                    log_system_event(f"[重试] 第 {attempt}/{max_retries} 次重试...")

                result = await solve_single_challenge(
                    challenge=challenge,
                    config=config,
                    stats=stats,
                    concurrent_semaphore=concurrent_semaphore,
                    attempt_history=attempt_history if attempt > 0 else None,
                )

                if result.get("success"):
                    break

                attempt_history.append({"attempt": attempt + 1, "strategy": "Orchestrator"})
                attempt += 1

            # 输出结果
            log_system_event("=" * 60)
            if result and result.get("success"):
                log_system_event(f"🎉 成功! FLAG: {result.get('flag')}")
            else:
                log_system_event("❌ 未成功")
            log_system_event("=" * 60)

        except KeyboardInterrupt:
            log_system_event("\n🛑 用户中断", level=logging.WARNING)
            break


async def run_multi_target_mode(
    web_file: Optional[str] = None,
    pwn_dir: Optional[str] = None,
    reverse_dir: Optional[str] = None,
    misc_dir: Optional[str] = None,
    crypto_dir: Optional[str] = None,
    forensics_dir: Optional[str] = None,
    concurrency: int = 5,
    dynamic_scan: bool = False,
    scan_interval: int = 60,
):
    """多目标并发模式"""
    from chying_agent.multi_target_manager import (
        MultiTargetManager,
        parse_web_challenges,
        parse_directory_challenges,
    )

    # 配置验证
    try:
        config = get_config_manager().config
    except Exception as e:
        log_system_event(f"❌ 配置加载失败: {e}", level=logging.ERROR)
        raise

    # 创建管理器
    manager = MultiTargetManager(
        config=config,
        max_retries=MAX_RETRIES,
        concurrency=concurrency,
    )

    if dynamic_scan:
        manager.enable_dynamic_scan(scan_interval=scan_interval, ctf_dir=None)
        log_system_event(f"[动态扫描] 已启用，间隔: {scan_interval}s")

    # 解析题目
    try:
        if web_file:
            manager.add_category("web", parse_web_challenges(web_file))
        if pwn_dir:
            manager.add_category("pwn", parse_directory_challenges(pwn_dir, "pwn"))
        if reverse_dir:
            manager.add_category("reverse", parse_directory_challenges(reverse_dir, "reverse"))
        if misc_dir:
            manager.add_category("misc", parse_directory_challenges(misc_dir, "misc"))
        if crypto_dir:
            manager.add_category("crypto", parse_directory_challenges(crypto_dir, "crypto"))
        if forensics_dir:
            manager.add_category("forensics", parse_directory_challenges(forensics_dir, "forensics"))
    except FileNotFoundError as e:
        log_system_event(f"❌ 文件不存在: {e}", level=logging.ERROR)
        raise

    await manager.run(dynamic_scan=dynamic_scan)


async def run_platform_mode(
    platform_url: str,
    concurrency: int = 5,
    category_filter: Optional[str] = None,
):
    """CTF 平台模式：scrape -> solve -> auto-submit。

    全流程由 PlatformRunner 编排，支持：
    - 有固定 URL 的题目并发做题
    - 需要场景的题目串行做题（平台场景互斥）
    - 做完自动提交 flag 到平台
    """
    from chying_agent.ctf_platform import PlatformRunner

    runner = PlatformRunner(
        platform_url=platform_url,
        concurrency=concurrency,
        max_retries=MAX_RETRIES,
        category_filter=category_filter,
    )
    await runner.run()


def main():
    """主入口"""
    parser = argparse.ArgumentParser(
        description="CHYing Agent - AI 驱动的自动化渗透测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py --ctf                                   # CTF 自动检测模式
  python main.py -t http://target:8080                   # 单目标模式
  python main.py -t target:8080 -r 3                     # 单目标 + 重试
  python main.py -t "http://web:8080,http://api:3000"    # 同题目多 URL
  python main.py -t "http://a:80" -t "http://b:81"      # 多个独立题目
  python main.py --web urls.txt -c 5                     # 多目标并发模式
  python main.py --reverse ./reverse_dir -c 3              # Reverse 题目目录
  python main.py --platform https://ctf.example.com -c 5 # CTF 平台自动模式
  python main.py --platform https://ctf.example.com --category web # 只跑 Web 分类
        """,
    )

    parser.add_argument("--ctf", action="store_true", help="CTF 自动检测模式")
    parser.add_argument("-t", "--target", action="append", help="目标 URL（可多次指定，逗号分隔表示同一题目的多个 URL）")
    parser.add_argument("-p", "--prompt", type=str, default="",
        help="题目描述或提示信息，直接注入到 Agent 执行上下文。支持 @filepath 从文件读取")

    multi_group = parser.add_argument_group("多目标并发模式")
    multi_group.add_argument("--web", type=str, help="Web 题目 URL 文件")
    multi_group.add_argument("--pwn", type=str, help="PWN 题目目录")
    multi_group.add_argument("--reverse", type=str, help="Reverse 题目目录")
    multi_group.add_argument("--misc", type=str, help="Misc 题目目录")
    multi_group.add_argument("--crypto", type=str, help="Crypto 题目目录")
    multi_group.add_argument("--forensics", type=str, help="Forensics 题目目录")
    multi_group.add_argument("-c", "--concurrency", type=int, default=5, help="并发数 (默认: 5)")
    multi_group.add_argument("--dynamic-scan", action="store_true", help="启用动态扫描")
    multi_group.add_argument("--scan-interval", type=int, default=60, help="扫描间隔秒数")

    parser.add_argument("-r", "--retry", type=int, default=0, help="最大重试次数")
    parser.add_argument("-m", "--mode", choices=AVAILABLE_MODES, default="ctf", help="运行模式")
    parser.add_argument("--skip-preflight", action="store_true", help="跳过启动检查")

    platform_group = parser.add_argument_group("CTF 平台模式")
    platform_group.add_argument(
        "--platform", type=str, help="CTF 平台 URL（需先在浏览器中登录）",
    )
    platform_group.add_argument(
        "--category", type=str, default=None,
        help="指定 CTF 分类（配合 --platform 使用，如 --category web）",
    )

    web_group = parser.add_argument_group("Web Dashboard")
    web_group.add_argument("--dashboard", action="store_true", help="启动 Web Dashboard API")
    web_group.add_argument("--dashboard-port", type=int, default=8080, help="Web Dashboard 端口 (默认: 8080)")

    args = parser.parse_args()

    # --prompt @filepath 支持：从文件读取 prompt 内容
    if args.prompt.startswith("@"):
        prompt_path = args.prompt[1:]
        try:
            with open(prompt_path, encoding="utf-8") as f:
                args.prompt = f.read()
        except FileNotFoundError:
            parser.error(f"Prompt 文件不存在: {prompt_path}")
        except OSError as e:
            parser.error(f"读取 prompt 文件失败: {e}")

    # 启动前检查
    if not args.skip_preflight:
        if not run_preflight_checks():
            return

    init_db()

    # Web Dashboard 模式
    if args.dashboard:
        import uvicorn
        from chying_agent.web.app import create_app

        app = create_app()
        log_system_event(f"🌐 启动 Web Dashboard: http://0.0.0.0:{args.dashboard_port}")
        uvicorn.run(app, host="0.0.0.0", port=args.dashboard_port)
        return

    # 模式选择
    has_multi = any([args.web, args.pwn, args.reverse, args.misc, args.crypto, args.forensics])
    modes_selected = sum([bool(args.target), has_multi, bool(args.ctf), bool(args.platform)])

    if modes_selected == 0:
        parser.error("必须指定运行模式: --ctf, -t, --platform, 或 --web/--pwn/--misc/--crypto")
    if modes_selected > 1:
        parser.error("运行模式互斥，只能选择一种")

    if args.platform:
        asyncio.run(run_platform_mode(
            platform_url=args.platform,
            concurrency=args.concurrency,
            category_filter=args.category,
        ))
    elif args.ctf:
        from chying_agent.multi_target_manager import auto_detect_ctf_challenges

        detected = auto_detect_ctf_challenges()
        if not detected["found"]:
            log_system_event("❌ 未检测到题目，请检查 agent-work/ctf/ 目录", level=logging.ERROR)
            return

        asyncio.run(run_multi_target_mode(
            web_file=detected.get("web_file"),
            pwn_dir=detected.get("pwn_dir"),
            reverse_dir=detected.get("reverse_dir"),
            misc_dir=detected.get("misc_dir"),
            crypto_dir=detected.get("crypto_dir"),
            forensics_dir=detected.get("forensics_dir"),
            concurrency=args.concurrency,
            dynamic_scan=args.dynamic_scan,
            scan_interval=args.scan_interval,
        ))
    elif args.target:
        asyncio.run(run_targets(args.target, max_retries=args.retry, mode=args.mode, prompt=args.prompt))
    elif has_multi:
        asyncio.run(run_multi_target_mode(
            web_file=args.web,
            pwn_dir=args.pwn,
            reverse_dir=args.reverse,
            misc_dir=args.misc,
            crypto_dir=args.crypto,
            forensics_dir=args.forensics,
            concurrency=args.concurrency,
            dynamic_scan=args.dynamic_scan,
            scan_interval=args.scan_interval,
        ))


if __name__ == "__main__":
    main()
    # 刷新 Langfuse 缓冲区，确保所有追踪数据发送完毕
    shutdown_observability()
    # Claude SDK 的 SubprocessCLITransport 通过 anyio.open_process 启动 Claude CLI，
    # CLI 又启动 MCP 子进程（如 chrome-devtools-mcp）。transport.close() 只对主进程
    # 发送 SIGTERM，MCP 子进程可能未被终止，导致 anyio 后台线程无法退出。
    # 在所有业务逻辑完成后用 os._exit 强制退出。
    os._exit(0)
