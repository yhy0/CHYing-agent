"""Sentinel Agent 提示模式启动器 - 2小时后带提示解题

使用场景：
- 与 main.py 同时启动，形成双重保障
- 等待 2 小时后，自动为所有未解决的题目获取提示
- 使用提示重新解题，提高成功率

运行方式：
    python main_with_hint.py

环境变量：
    HINT_DELAY_HOURS: 延迟启动时间（小时），默认 2
    MAX_CONCURRENT_TASKS: 最大并发任务数，默认 8
    MAX_RETRIES: 最大重试次数，默认 4
"""
import asyncio
import os
import logging
from datetime import datetime, timedelta
from langfuse import get_client
from langfuse.langchain import CallbackHandler

from sentinel_agent.core.singleton import get_config_manager
from sentinel_agent.task_manager import ChallengeTaskManager
from sentinel_agent.retry_strategy import RetryStrategy
from sentinel_agent.task_launcher import start_challenge_task
from sentinel_agent.scheduler import (
    status_monitor,
    check_and_start_pending_challenges,
    periodic_fetch_challenges
)
from sentinel_agent.common import log_system_event
from sentinel_agent.utils.util import fetch_new_challenges


# ==================== 配置 ====================
HINT_DELAY_HOURS = float(os.getenv("HINT_DELAY_HOURS", "2.0"))  # 默认 2 小时
MAX_CONCURRENT_TASKS = int(os.getenv("MAX_CONCURRENT_TASKS", "8"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "4"))

concurrent_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)


async def fetch_hints_for_unsolved_challenges(api_client, task_manager):
    """
    为所有未解决的题目获取提示
    
    ⚠️ 重要：只为未解决的题目获取提示，避免浪费扣分！
    
    Args:
        api_client: API 客户端
        task_manager: 任务管理器
        
    Returns:
        带提示的题目列表
    """
    log_system_event("[提示获取] 开始获取未解决题目的提示...")
    
    # 1. 获取所有未解决的题目
    unsolved_challenges = await fetch_new_challenges(api_client)
    
    if not unsolved_challenges:
        log_system_event("[提示获取] 没有未解决的题目")
        return []
    
    log_system_event(
        f"[提示获取] 发现 {len(unsolved_challenges)} 道未解决题目",
        {"题目列表": [ch.get('challenge_code') for ch in unsolved_challenges]}
    )
    
    # 2. 为每道题获取提示
    challenges_with_hints = []
    success_count = 0
    failed_count = 0
    skipped_count = 0  # ⭐ 跳过计数（已有提示或已解决）
    
    for challenge in unsolved_challenges:
        challenge_code = challenge.get("challenge_code", "unknown")
        
        # ⭐ 安全检查 1: 如果题目已解决，跳过（虽然 fetch_new_challenges 已过滤，但双重保险）
        if challenge.get("solved", False):
            log_system_event(f"[提示获取] {challenge_code} 已解决，跳过获取提示（避免浪费扣分和消耗 token ）")
            skipped_count += 1
                            # 检查是否允许重新攻击已解决的题目（调试模式）
            import os
            allow_resolved = os.getenv("DEBUG_ALLOW_RESOLVED", "false").lower() == "true"

            if allow_resolved:
                # 在调试模式下，跳过已解决检查
                log_system_event(f"调试模式，允许重新攻击已解决的题目: {challenge_code}")
                pass
            else:
                continue
        # 下面的 AI 写的有问题， 这里注释调， 导致这个没有获取到提示，跳过了， 重复获取提示也不会扣分
        # # ⭐ 安全检查 2: 如果已经查看过提示，跳过（避免重复扣分）
        # if challenge.get("hint_viewed", False):
        #     log_system_event(f"[提示获取] {challenge_code} 已有提示，跳过重复获取")
        #     # 仍然添加到列表（使用已有提示）
        #     challenges_with_hints.append(challenge)
        #     skipped_count += 1
        #     continue
        
        try:
            # ⭐ 调用 API 获取提示（只有第一次才会扣分！）
            log_system_event(
                f"[提示获取] 🔍 为 {challenge_code} 获取提示, 警告: 获取提示后解题成功会扣除惩罚分",
                {}
            )
            
            hint_data = api_client.get_hint(challenge_code)
            hint_content = hint_data.get("hint_content", "")
            first_use = hint_data.get("first_use", False)  # ⭐ 获取首次使用标识
            penalty_points = hint_data.get("penalty_points", 0)
            
            # 将提示添加到 challenge 数据中
            challenge["hint_content"] = hint_content
            challenge["hint_viewed"] = True
            challenge["hint_penalty_points"] = penalty_points
            
            challenges_with_hints.append(challenge)
            success_count += 1
            
            # ⭐ 根据 first_use 提供更明确的日志
            if first_use:
                log_system_event(
                    f"[提示获取] ✓ {challenge_code} 提示获取成功（首次查看，会扣分）",
                    {
                        "提示预览": hint_content,
                        "惩罚分": penalty_points,
                        "首次查看": True
                    }
                )
            else:
                log_system_event(
                    f"[提示获取] ✓ {challenge_code} 提示获取成功（重复查看，不扣分）",
                    {
                        "提示预览": hint_content,
                        "惩罚分": penalty_points,
                        "首次查看": False
                    }
                )
            
        except Exception as e:
            failed_count += 1
            log_system_event(
                f"[提示获取] ✗ {challenge_code} 提示获取失败: {str(e)}",
                level=logging.WARNING
            )
            # 即使获取提示失败，仍然添加到列表（无提示解题）
            challenges_with_hints.append(challenge)
    
    log_system_event(
        "[提示获取] 提示获取完成",
        {
            "成功获取": success_count,
            "失败": failed_count,
            "跳过（已有提示/已解决）": skipped_count,
            "总计未解决": len(unsolved_challenges)
        }
    )
    
    return challenges_with_hints


async def main():
    """主函数 - 2小时后带提示解题模式"""
    
    # ==================== 0. 启动提示 ====================
    print("\n" + "="*80)
    print("🕐 Sentinel Agent 提示模式启动器")
    print("="*80)
    print(f"⏰ 延迟时间: {HINT_DELAY_HOURS} 小时")
    print(f"🎯 目标: 2小时后为未解决题目获取提示，重新解题")
    print(f"🔄 并发数: {MAX_CONCURRENT_TASKS}")
    print(f"🔁 重试次数: {MAX_RETRIES}")
    
    # 计算启动时间
    start_time = datetime.now()
    wake_time = start_time + timedelta(hours=HINT_DELAY_HOURS)
    
    print(f"\n⏱️  当前时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⏱️  启动时间: {wake_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80 + "\n")
    
    # ==================== 1. 等待指定时间 ====================
    sleep_seconds = HINT_DELAY_HOURS * 3600
    log_system_event(
        f"[休眠] 进入休眠模式，{HINT_DELAY_HOURS} 小时后启动...",
        {"休眠秒数": sleep_seconds}
    )
    
    # 每 30 分钟打印一次倒计时
    remaining = sleep_seconds
    while remaining > 0:
        if remaining <= 60:
            # 最后 1 分钟，每 10 秒打印一次
            sleep_time = min(10, remaining)
            await asyncio.sleep(sleep_time)
            remaining -= sleep_time  # ✅ 避免负数
            if remaining > 0:
                print(f"⏳ 距离启动还有 {remaining:.0f} 秒...")
        elif remaining <= 1800:
            # 最后 30 分钟，每分钟打印一次
            await asyncio.sleep(60)
            remaining -= 60
            if remaining > 0:  # ✅ 只在 remaining > 0 时打印
                print(f"⏳ 距离启动还有 {remaining // 60:.0f} 分钟...")
        else:
            # 每 30 分钟打印一次
            await asyncio.sleep(1800)
            remaining -= 1800
            hours = remaining // 3600
            minutes = (remaining % 3600) // 60
            print(f"⏳ 距离启动还有 {hours} 小时 {minutes} 分钟...")
    
    # ==================== 2. 初始化配置 ====================
    log_system_event(
        "\n" + "="*80 + "\n" +
        f"🚀 提示模式正式启动！（{datetime.now().strftime('%H:%M:%S')}）\n" +
        "="*80
    )
    
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
    
    # ==================== 3. 初始化 Langfuse ====================
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
    
    # ==================== 4. 初始化重试策略 ====================
    try:
        retry_strategy = RetryStrategy(config=config)
        log_system_event("[✓] 重试策略初始化完成")
    except ValueError as e:
        log_system_event(
            f"❌ 重试策略初始化失败（配置错误）: {str(e)}",
            level=logging.ERROR
        )
        raise
    
    # ==================== 5. 初始化 API 客户端 ====================
    try:
        from sentinel_agent.tools.competition_api_tools import CompetitionAPIClient
        api_client = CompetitionAPIClient()
        log_system_event("[✓] API 客户端初始化完成")
    except Exception as e:
        log_system_event(
            f"❌ API 客户端初始化失败: {str(e)}",
            level=logging.ERROR
        )
        raise
    
    # ==================== 6. 初始化任务管理器 ====================
    task_manager = ChallengeTaskManager(max_retries=MAX_RETRIES)
    log_system_event(f"[✓] 任务管理器初始化完成（最大重试: {MAX_RETRIES}）")
    
    # ==================== 7. 获取未解决题目的提示 ====================
    try:
        challenges_with_hints = await fetch_hints_for_unsolved_challenges(
            api_client=api_client,
            task_manager=task_manager
        )
    except Exception as e:
        log_system_event(
            f"❌ 获取提示失败: {str(e)}",
            {
                "错误类型": type(e).__name__,
                "建议": "将继续以无提示模式运行，使用已拉取的题目列表"
            },
            level=logging.ERROR
        )
        # 发生异常时，尝试只获取题目列表（不获取提示）
        try:
            challenges_with_hints = await fetch_new_challenges(api_client)
            log_system_event(
                f"[降级模式] 成功获取 {len(challenges_with_hints)} 道题目（无提示）",
                {"警告": "将以无提示模式解题"}
            )
        except Exception as fallback_error:
            log_system_event(
                f"❌ 降级模式也失败: {str(fallback_error)}，程序无法继续运行",
                level=logging.CRITICAL
            )
            raise
    
    if not challenges_with_hints:
        log_system_event(
            "🎉 所有题目已解决，无需启动提示模式！",
            level=logging.INFO
        )
        return
    
    # ==================== 8. 创建任务启动函数 ====================
    async def start_task_wrapper(challenge, retry_strategy, config, langfuse_handler):
        """任务启动包装函数（带提示注入）"""
        challenge_code = challenge.get("challenge_code", "unknown")
        
        # ⭐ 核心：将提示注入到任务中
        hint_content = challenge.get("hint_content")
        if hint_content:
            log_system_event(
                f"[提示注入] 为 {challenge_code} 注入提示",
                {"提示长度": len(hint_content)}
            )
        
        return await start_challenge_task(
            challenge=challenge,
            retry_strategy=retry_strategy,
            config=config,
            langfuse_handler=langfuse_handler,
            task_manager=task_manager,
            concurrent_semaphore=concurrent_semaphore
        )
    
    # ==================== 9. 启动带提示的解题任务 ====================
    log_system_event(
        f"[任务启动] 开始启动 {len(challenges_with_hints)} 个带提示的解题任务..."
    )
    
    started_count = 0
    for challenge in challenges_with_hints:
        challenge_code = challenge.get("challenge_code", "unknown")
        
         # ⭐ 添加调试日志
        if challenge.get("hint_content"):
            log_system_event(
                f"[调试] {challenge_code} 确认有提示",
                {"提示": challenge["hint_content"][:50]}
            )
        else:
            log_system_event(
                f"[调试] {challenge_code} 没有提示！",
                level=logging.WARNING
            )
        if await start_task_wrapper(
            challenge=challenge,
            retry_strategy=retry_strategy,
            config=config,
            langfuse_handler=langfuse_handler
        ):
            started_count += 1
            log_system_event(f"[任务启动] ✓ 启动任务: {challenge_code}")
        
        # 避免并发过多
        if started_count >= MAX_CONCURRENT_TASKS:
            log_system_event(
                f"[任务启动] 已达并发上限 ({MAX_CONCURRENT_TASKS})，等待任务完成..."
            )
            break
    
    log_system_event(
        f"[任务启动] 共启动 {started_count} 个任务",
        {"总题目数": len(challenges_with_hints)}
    )
    
    # ==================== 10. 设置任务完成回调（动态填充） ====================
    async def refill_slots_callback():
        """任务完成后立即填充空位"""
        log_system_event("[立即回填] 任务完成，触发空位回填...")
        
        # 继续启动剩余的带提示任务
        await check_and_start_pending_challenges(
            api_client=api_client,
            task_manager=task_manager,
            retry_strategy=retry_strategy,
            config=config,
            langfuse_handler=langfuse_handler,
            start_task_func=start_task_wrapper,
            max_concurrent_tasks=MAX_CONCURRENT_TASKS
        )
    
    task_manager.set_completion_callback(refill_slots_callback)
    log_system_event("[✓] 已设置动态填充机制")
    
    # ==================== 11. 启动后台任务 ====================
    # 定时拉取新题目的任务（只拉取未解决的题目）
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
            "监控间隔": f"{monitor_interval//60} 分钟"
        }
    )
    
    # ==================== 12. 持续运行 ====================
    log_system_event(
        "\n" + "="*80 + "\n" +
        "💡 提示模式正式运行中...\n" +
        "="*80
    )
    
    try:
        # 等待所有后台任务（无限期运行）
        await asyncio.gather(fetch_task, monitor_task)
    except KeyboardInterrupt:
        log_system_event("\n[*] 收到退出信号，正在优雅关闭...")
        
        # 取消后台任务
        fetch_task.cancel()
        monitor_task.cancel()
        
        # 等待后台任务完成取消
        try:
            await asyncio.gather(fetch_task, monitor_task, return_exceptions=True)
        except Exception:
            pass
        
        # 打印最终状态
        final_status = await task_manager.get_status()
        print("\n" + "="*80)
        print("📊 提示模式最终状态")
        print("="*80)
        print(f"已完成: {final_status['completed_count']} 个")
        print(f"失败: {final_status['failed_count']} 个")
        print(f"未完成: {final_status['active_count']} 个")
        print("="*80 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 提示模式已退出")
    except Exception as e:
        print(f"\n❌ 提示模式异常退出: {str(e)}")
        raise
