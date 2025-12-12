"""CHYing Agent 主程序 - 支持多种运行模式

运行模式：
1. 单目标模式 (-t): 直接指定目标 URL 进行渗透测试
   示例: python main.py -t http://192.168.1.100:8080

2. 比赛模式 (-api): 通过 API 获取题目，持续运行
   示例: python main.py -api

比赛模式架构：
- 持续运行，不自动退出
- 每 10 分钟定时拉取新题目
- 为每道题创建独立的 Agent 实例（异步并发）
- 动态管理解题任务队列（新题自动加入，完成自动清理）
- ⭐ 失败题目自动重试（角色互换 + 历史记录传承）
- ⭐ 任务完成后动态填充槽位
- 实时汇总得分和进度

模块化设计：
- task_manager.py: 任务生命周期管理
- retry_strategy.py: 重试策略（角色互换）
- challenge_solver.py: 单题解题逻辑
- task_launcher.py: 任务启动器
- scheduler.py: 定时任务和监控
- utils/utils.py: 工具函数
"""
import argparse
import asyncio
import os
import logging
from urllib.parse import urlparse
from langfuse import get_client
from langfuse.langchain import CallbackHandler

from chying_agent.core.singleton import get_config_manager
from chying_agent.task_manager import ChallengeTaskManager
from chying_agent.retry_strategy import RetryStrategy
from chying_agent.common import log_system_event


# ==================== 并发控制 ====================
MAX_CONCURRENT_TASKS = int(os.getenv("MAX_CONCURRENT_TASKS", "8"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "4"))  # 4 次重试 = 共 5 次机会（首次 + 4 次重试）


def parse_target_url(target: str) -> dict:
    """
    解析目标 URL，构造虚拟 challenge 对象

    支持格式：
    - http://192.168.1.100:8080
    - https://example.com
    - 192.168.1.100:8080 (默认 http)
    - 192.168.1.100 (默认端口 80)

    Returns:
        虚拟 challenge 字典
    """
    # 如果没有协议前缀，添加 http://
    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"

    parsed = urlparse(target)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    # 构造虚拟 challenge
    challenge = {
        "challenge_code": f"manual_{host}_{port}",
        "difficulty": "unknown",
        "points": 0,
        "hint_viewed": False,
        "solved": False,
        "target_info": {
            "ip": host,  # 保持字段名兼容，实际可能是域名
            "port": [port]
        },
        # 标记为手动模式，跳过 API 调用
        "_manual_mode": True,
        "_target_url": target
    }

    return challenge


async def run_single_target(target: str, max_retries: int = 0):
    """
    单目标模式 - 直接对指定目标进行渗透测试

    Args:
        target: 目标 URL (如 http://192.168.1.100:8080)
        max_retries: 最大重试次数 (默认 0，不重试)
    """
    from chying_agent.challenge_solver import solve_single_challenge

    # ==================== 0. 配置验证 ====================
    try:
        config_manager = get_config_manager()
        config = config_manager.config
    except Exception as e:
        log_system_event(
            f"❌ 配置加载失败: {str(e)}\n"
            "请确保 .env 文件中包含必需的配置项",
            level=logging.ERROR
        )
        raise

    # ==================== 1. 解析目标 ====================
    challenge = parse_target_url(target)

    log_system_event(
        "=" * 80 + "\n" +
        "🎯 CHYing Agent 单目标模式启动\n" +
        "=" * 80
    )
    log_system_event(
        f"[目标信息]",
        {
            "URL": challenge["_target_url"],
            "IP": challenge["target_info"]["ip"],
            "端口": challenge["target_info"]["port"],
            "任务ID": challenge["challenge_code"]
        }
    )

    # ==================== 2. 初始化 Langfuse ====================
    challenge_code = challenge["challenge_code"]
    target_url = challenge["_target_url"]
    try:
        get_client()  # 验证连接
        # Langfuse 3.x: update_trace=True 让 trace 使用 chain 的 name/input/output
        langfuse_handler = CallbackHandler(update_trace=True)
        log_system_event("[✓] Langfuse 初始化完成")
    except Exception as e:
        log_system_event(
            f"⚠️ Langfuse 初始化失败，将继续运行: {str(e)}",
            level=logging.WARNING
        )
        langfuse_handler = None

    # Langfuse 元数据（通过 RunnableConfig 传递）
    langfuse_metadata = {
        "langfuse_session_id": challenge_code,
        "langfuse_tags": ["ctf", "manual"],
        "target": target_url
    }

    # ==================== 3. 初始化重试策略 ====================
    try:
        retry_strategy = RetryStrategy(config=config)
        log_system_event("[✓] 重试策略初始化完成")
    except ValueError as e:
        log_system_event(
            f"❌ 重试策略初始化失败（配置错误）: {str(e)}",
            level=logging.ERROR
        )
        raise

    # ==================== 4. 初始化任务管理器 ====================
    task_manager = ChallengeTaskManager(max_retries=max_retries)
    concurrent_semaphore = asyncio.Semaphore(1)  # 单目标模式只需要 1 个并发

    # ==================== 5. 获取 LLM 对 ====================
    main_llm, advisor_llm, strategy_desc = retry_strategy.get_llm_pair(0)
    log_system_event(f"[✓] LLM 策略: {strategy_desc}")

    # ==================== 6. 开始渗透测试 ====================
    if max_retries > 0:
        log_system_event(f"[重试] 最大重试次数: {max_retries}")

    log_system_event(
        "\n" + "="*80 + "\n" +
        "🚀 开始渗透测试...\n" +
        "- 按 Ctrl+C 可以中断\n" +
        "="*80
    )

    attempt = 0
    result = None
    attempt_history = []

    try:
        while attempt <= max_retries:
            if attempt > 0:
                log_system_event(f"\n[重试] 第 {attempt}/{max_retries} 次重试...")
                # 角色互换
                main_llm, advisor_llm, strategy_desc = retry_strategy.get_llm_pair(attempt)
                log_system_event(f"[✓] LLM 策略: {strategy_desc}")

            result = await solve_single_challenge(
                challenge=challenge,
                main_llm=main_llm,
                advisor_llm=advisor_llm,
                config=config,
                langfuse_handler=langfuse_handler,
                task_manager=task_manager,
                concurrent_semaphore=concurrent_semaphore,
                retry_strategy=retry_strategy,
                attempt_history=attempt_history if attempt > 0 else None,
                strategy_description=strategy_desc,
                langfuse_metadata=langfuse_metadata
            )

            # 成功则退出循环
            if result.get("success"):
                break

            # 记录本次尝试历史
            attempt_history.append({
                "attempt": attempt + 1,
                "summary": result.get("summary", "未知"),
                "attempts_count": result.get("attempts", 0)
            })

            attempt += 1

        # ==================== 7. 输出结果 ====================
        log_system_event("\n" + "="*80)
        if result and result.get("success"):
            log_system_event(
                f"🎉 渗透测试成功！",
                {
                    "FLAG": result.get("flag", "N/A"),
                    "尝试次数": result.get("attempts", 0),
                    "重试次数": attempt
                }
            )
        else:
            log_system_event(
                f"❌ 渗透测试未成功",
                {
                    "尝试次数": result.get("attempts", 0) if result else 0,
                    "重试次数": attempt,
                    "原因": "未找到 FLAG 或达到最大尝试次数"
                }
            )
        log_system_event("="*80)

    except KeyboardInterrupt:
        log_system_event(
            "\n🛑 收到中断信号，正在退出...",
            level=logging.WARNING
        )
    except Exception as e:
        log_system_event(
            f"❌ 渗透测试异常: {str(e)}",
            level=logging.ERROR
        )
        raise


async def run_api_mode():
    """比赛模式 - 通过 API 获取题目，持续运行"""
    # 延迟导入，仅在比赛模式使用
    from chying_agent.task_launcher import start_challenge_task
    from chying_agent.scheduler import (
        check_and_start_pending_challenges,
        periodic_fetch_challenges,
        status_monitor,
        print_final_status
    )

    # ==================== 0. 配置验证 ====================
    try:
        config_manager = get_config_manager()
        config = config_manager.config
    except Exception as e:
        log_system_event(
            f"❌ 配置加载失败: {str(e)}\n"
            "请确保 .env 文件中包含必需的配置项",
            level=logging.ERROR
        )
        raise

    # ==================== 1. 初始化全局变量 ====================
    concurrent_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    task_manager = ChallengeTaskManager(max_retries=MAX_RETRIES)

    log_system_event(
        f"[并发控制] 最大并发任务数: {MAX_CONCURRENT_TASKS}",
        {"可通过环境变量 MAX_CONCURRENT_TASKS 调整"}
    )
    log_system_event(
        f"[重试策略] 最大重试次数: {MAX_RETRIES}（共 {MAX_RETRIES + 1} 次机会）",
        {"可通过环境变量 MAX_RETRIES 调整"}
    )

    log_system_event(
        "=" * 80 + "\n" +
        "🚀 CHYing Agent 比赛模式启动\n" +
        "=" * 80
    )

    # ==================== 2. 初始化 Langfuse ====================
    try:
        get_client()  # 验证连接
        langfuse_handler = CallbackHandler()
        log_system_event("[✓] Langfuse 初始化完成")
    except Exception as e:
        log_system_event(
            f"⚠️ Langfuse 初始化失败，将继续运行: {str(e)}",
            level=logging.WARNING
        )
        langfuse_handler = None

    # ==================== 3. 初始化重试策略 ====================
    try:
        retry_strategy = RetryStrategy(config=config)
        log_system_event("[✓] 重试策略初始化完成")
    except ValueError as e:
        log_system_event(
            f"❌ 重试策略初始化失败（配置错误）: {str(e)}",
            level=logging.ERROR
        )
        raise

    # ==================== 4. 初始化 API 客户端 ====================
    try:
        from chying_agent.tools.competition_api_tools import CompetitionAPIClient
        api_client = CompetitionAPIClient()
        log_system_event("[✓] API 客户端初始化完成")
    except Exception as e:
        log_system_event(
            f"❌ API 客户端初始化失败: {str(e)}",
            level=logging.ERROR
        )
        raise

    # ==================== 5. 创建任务启动函数（闭包） ====================
    async def start_task_wrapper(challenge, retry_strategy, config, langfuse_handler):
        """任务启动包装函数"""
        return await start_challenge_task(
            challenge=challenge,
            retry_strategy=retry_strategy,
            config=config,
            langfuse_handler=langfuse_handler,
            task_manager=task_manager,
            concurrent_semaphore=concurrent_semaphore
        )

    # ⭐ 创建空位回填回调函数（立即重试）
    async def refill_slots_callback():
        """
        任务完成后立即触发的空位回填回调

        作用：
        - 失败任务完成后，立即启动重试或新任务
        - 避免等待 10 分钟的定时任务
        - 提高并发槽位利用率
        """
        log_system_event("[立即回填] 任务完成，触发空位回填...")
        await check_and_start_pending_challenges(
            api_client=api_client,
            task_manager=task_manager,
            retry_strategy=retry_strategy,
            config=config,
            langfuse_handler=langfuse_handler,
            start_task_func=start_task_wrapper,
            max_concurrent_tasks=MAX_CONCURRENT_TASKS
        )

    # ⭐ 设置任务完成回调
    task_manager.set_completion_callback(refill_slots_callback)
    log_system_event("[✓] 已设置立即回填机制（任务完成后自动填充空位）")

    # ==================== 6. 首次拉取题目并启动初始任务 ====================
    log_system_event("[*] 首次拉取题目...")
    await check_and_start_pending_challenges(
        api_client=api_client,
        task_manager=task_manager,
        retry_strategy=retry_strategy,
        config=config,
        langfuse_handler=langfuse_handler,
        start_task_func=start_task_wrapper,
        max_concurrent_tasks=MAX_CONCURRENT_TASKS
    )

    # ==================== 7. 启动后台任务 ====================
    # 定时拉取新题目的任务
    fetch_interval = int(os.getenv("FETCH_INTERVAL_SECONDS", "600"))
    fetch_task = asyncio.create_task(
        periodic_fetch_challenges(
            api_client=api_client,
            task_manager=task_manager,
            retry_strategy=retry_strategy,
            config=config,
            langfuse_handler=langfuse_handler,
            start_task_func=start_task_wrapper,
            max_concurrent_tasks=MAX_CONCURRENT_TASKS,
            interval_seconds=fetch_interval
        )
    )

    # 状态监控任务
    monitor_interval = int(os.getenv("MONITOR_INTERVAL_SECONDS", "300"))
    monitor_task = asyncio.create_task(
        status_monitor(
            task_manager=task_manager,
            interval_seconds=monitor_interval
        )
    )

    log_system_event(
        "[✓] 后台任务启动完成",
        {
            "定时拉取间隔": f"{fetch_interval//60} 分钟",
            "状态监控间隔": f"{monitor_interval//60} 分钟"
        }
    )

    # ==================== 8. 持续运行 ====================
    log_system_event(
        "\n" + "="*80 + "\n" +
        "✅ 系统正在运行中...\n" +
        "- 按 Ctrl+C 可以优雅退出\n" +
        "- 系统会自动拉取新题目并创建解题任务\n" +
        "- 失败的题目会自动重试（角色互换）\n" +
        "- 任务完成后会动态填充槽位\n" +
        "="*80
    )

    try:
        # 等待所有后台任务（无限期运行）
        await asyncio.gather(fetch_task, monitor_task)
    except KeyboardInterrupt:
        log_system_event(
            "\n🛑 收到中断信号，正在优雅退出...",
            level=logging.WARNING
        )

        # 取消后台任务
        fetch_task.cancel()
        monitor_task.cancel()

        # 等待后台任务完成取消
        try:
            await asyncio.gather(fetch_task, monitor_task, return_exceptions=True)
        except Exception:
            pass

        # 打印最终状态
        await print_final_status(task_manager)

        log_system_event("👋 程序已退出")


def main():
    """主入口 - 解析命令行参数并选择运行模式"""
    parser = argparse.ArgumentParser(
        description="CHYing Agent - AI 驱动的自动化渗透测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 单目标模式 - 直接指定目标进行渗透测试
  python main.py -t http://192.168.1.100:8080
  python main.py -t https://example.com
  python main.py -t 192.168.1.100:8080

  # 单目标模式 + 重试
  python main.py -t http://192.168.1.100:8080 -r 3

  # 比赛模式 - 通过 API 获取题目
  python main.py -api
  python main.py --api
        """
    )

    # 互斥参数组
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "-t", "--target",
        type=str,
        metavar="URL",
        help="单目标模式: 指定目标 URL (如 http://192.168.1.100:8080)"
    )
    mode_group.add_argument(
        "-api", "--api",
        action="store_true",
        help="比赛模式: 通过 API 获取题目，持续运行"
    )

    # 可选参数
    parser.add_argument(
        "-r", "--retry",
        type=int,
        default=0,
        metavar="N",
        help="单目标模式: 最大重试次数 (默认 0，不重试)"
    )

    args = parser.parse_args()

    # 根据参数选择运行模式
    if args.target:
        asyncio.run(run_single_target(args.target, max_retries=args.retry))
    elif args.api:
        asyncio.run(run_api_mode())


if __name__ == "__main__":
    main()
