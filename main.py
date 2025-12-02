"""CHYing Agent 主程序 - 持续运行的多 Agent 并发解题模式

架构：
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
import asyncio
import os
import logging
from langfuse import get_client
from langfuse.langchain import CallbackHandler

from chying_agent.core.singleton import get_config_manager
from chying_agent.task_manager import ChallengeTaskManager
from chying_agent.retry_strategy import RetryStrategy
from chying_agent.task_launcher import start_challenge_task
from chying_agent.scheduler import (
    check_and_start_pending_challenges,
    periodic_fetch_challenges,
    status_monitor,
    print_final_status
)
from chying_agent.common import log_system_event


# ==================== 并发控制 ====================
MAX_CONCURRENT_TASKS = int(os.getenv("MAX_CONCURRENT_TASKS", "8"))
concurrent_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)

log_system_event(
    f"[并发控制] 最大并发任务数: {MAX_CONCURRENT_TASKS}",
    {"可通过环境变量 MAX_CONCURRENT_TASKS 调整"}
)


# ==================== 全局任务管理器 ====================
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "4"))  # 4 次重试 = 共 5 次机会（首次 + 4 次重试）
task_manager = ChallengeTaskManager(max_retries=MAX_RETRIES)

log_system_event(
    f"[重试策略] 最大重试次数: {MAX_RETRIES}（共 {MAX_RETRIES + 1} 次机会）",
    {"可通过环境变量 MAX_RETRIES 调整"}
)


async def main():
    """主函数 - 持续运行的并发解题模式"""
    # ==================== 0. 配置验证 ====================
    # ⭐ 修复：提前验证必需的环境变量，提供友好的错误提示
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
    
    # ==================== 1. 初始化配置 ====================
    log_system_event(
        "=" * 80 + "\n" +
        "🚀 CHYing Agent 持续运行模式启动（完全重构版）\n" +
        "=" * 80
    )

    # ==================== 2. 初始化 Langfuse ====================
    try:
        langfuse = get_client()
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

    # ⭐ 新增：创建空位回填回调函数（立即重试）
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


if __name__ == "__main__":
    asyncio.run(main())
