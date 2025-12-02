"""
调度器模块
==========

负责定时任务和状态监控：
- 定时拉取新题目
- 动态填充槽位
- 状态监控和汇总
"""
import asyncio
import logging
from typing import Dict

from chying_agent.common import log_system_event
from chying_agent.utils.util import fetch_new_challenges


async def check_and_start_pending_challenges(
    api_client,
    task_manager,
    retry_strategy,
    config,
    langfuse_handler,
    start_task_func,  # 传入启动任务的函数
    max_concurrent_tasks: int
):
    """
    检查并启动待处理的题目（动态填充空闲槽位）

    在任务完成后调用，确保并发槽位始终被充分利用

    Args:
        api_client: API 客户端
        task_manager: 任务管理器
        retry_strategy: 重试策略
        config: 配置
        langfuse_handler: Langfuse 回调
        start_task_func: 启动任务的函数
        max_concurrent_tasks: 最大并发任务数
    """
    # 获取当前活跃任务数
    status = await task_manager.get_status()
    active_count = status['active_count']

    # 如果还有空闲槽位
    if active_count < max_concurrent_tasks:
        # 拉取未解决的题目
        unsolved_challenges = await fetch_new_challenges(api_client)

        # ⭐ 优先处理失败但可重试的题目（线程安全）
        retry_candidates = []
        new_challenges = []

        for challenge in unsolved_challenges:
            challenge_code = challenge.get("challenge_code", "unknown")
            # ⭐ 修复：使用 await 调用异步方法
            if await task_manager.should_retry(challenge_code):
                retry_candidates.append(challenge)
            else:
                new_challenges.append(challenge)

        # 合并：重试题目优先
        all_candidates = retry_candidates + new_challenges

        # 启动新任务，直到槽位满或没有题目
        started_count = 0
        for challenge in all_candidates:
            if active_count >= max_concurrent_tasks:
                break

            challenge_code = challenge.get("challenge_code", "unknown")

            # 调用传入的启动任务函数
            if await start_task_func(
                challenge=challenge,
                retry_strategy=retry_strategy,
                config=config,
                langfuse_handler=langfuse_handler
            ):
                active_count += 1
                started_count += 1

                # ⭐ 修复：使用 await 调用异步方法（线程安全）
                retry_count = await task_manager.get_retry_count(challenge_code)
                if retry_count > 0:
                    log_system_event(
                        f"[动态填充] 🔄 重试任务: {challenge_code} (第 {retry_count + 1} 次尝试)",
                        {"当前活跃任务": active_count}
                    )
                else:
                    log_system_event(
                        f"[动态填充] 🆕 启动新任务: {challenge_code}",
                        {"当前活跃任务": active_count}
                    )

        if started_count > 0:
            log_system_event(
                f"[动态填充] ✅ 本轮启动 {started_count} 个任务"
            )


async def periodic_fetch_challenges(
    api_client,
    task_manager,
    retry_strategy,
    config,
    langfuse_handler,
    start_task_func,
    max_concurrent_tasks: int,
    interval_seconds: int = 600  # 默认 10 分钟
):
    """
    定时拉取新题目的后台任务

    Args:
        api_client: API 客户端
        task_manager: 任务管理器
        retry_strategy: 重试策略
        config: 配置
        langfuse_handler: Langfuse 回调
        start_task_func: 启动任务的函数
        max_concurrent_tasks: 最大并发任务数
        interval_seconds: 拉取间隔（秒）
    """
    log_system_event(
        f"[定时任务] 启动定时拉取任务（每 {interval_seconds//60} 分钟）"
    )

    while True:
        try:
            # ⭐ 调用动态填充函数
            await check_and_start_pending_challenges(
                api_client=api_client,
                task_manager=task_manager,
                retry_strategy=retry_strategy,
                config=config,
                langfuse_handler=langfuse_handler,
                start_task_func=start_task_func,
                max_concurrent_tasks=max_concurrent_tasks
            )

            # 打印当前状态
            status = await task_manager.get_status()
            log_system_event(
                f"[定时任务] 当前状态",
                {
                    "活跃任务": status['active_count'],
                    "已完成": status['completed_count'],
                    "失败": status['failed_count']
                }
            )

            # 等待下一次拉取
            await asyncio.sleep(interval_seconds)

        except asyncio.CancelledError:
            log_system_event("[定时任务] 收到停止信号，退出定时任务")
            break
        except Exception as e:
            log_system_event(
                f"[定时任务] 发生错误: {str(e)}，将在下一轮重试",
                level=logging.ERROR
            )
            await asyncio.sleep(interval_seconds)


async def status_monitor(task_manager, interval_seconds: int = 300):
    """
    状态监控任务 - 定期打印系统状态

    Args:
        task_manager: 任务管理器
        interval_seconds: 监控间隔（秒）
    """
    log_system_event(
        f"[状态监控] 启动状态监控任务（每 {interval_seconds//60} 分钟）"
    )

    while True:
        try:
            await asyncio.sleep(interval_seconds)

            status = await task_manager.get_status()

            print("\n" + "="*80)
            print("📊 系统状态汇总")
            print("="*80)
            print(f"活跃任务: {status['active_count']} 个")
            print(f"已完成: {status['completed_count']} 个")
            print(f"失败: {status['failed_count']} 个")

            if status['active_tasks']:
                print(f"\n🔄 正在解题: {', '.join(status['active_tasks'])}")

            if status['completed_tasks']:
                print(f"\n✅ 已完成: {', '.join(status['completed_tasks'])}")

            if status['failed_tasks']:
                print("\n❌ 失败题目:")
                for code, count in status['failed_tasks'].items():
                    print(f"  - {code}: {count} 次失败")

            print("="*80 + "\n")

        except asyncio.CancelledError:
            log_system_event("[状态监控] 收到停止信号，退出监控任务")
            break
        except Exception as e:
            log_system_event(
                f"[状态监控] 发生错误: {str(e)}",
                level=logging.ERROR
            )


async def print_final_status(task_manager):
    """
    打印最终状态汇总

    Args:
        task_manager: 任务管理器
    """
    final_status = await task_manager.get_status()
    print("\n" + "="*80)
    print("📊 最终状态汇总")
    print("="*80)
    print(f"已完成: {final_status['completed_count']} 个")
    print(f"失败: {final_status['failed_count']} 个")
    print(f"未完成: {final_status['active_count']} 个")

    if final_status['completed_tasks']:
        print(f"\n✅ 已完成题目: {', '.join(final_status['completed_tasks'])}")

    if final_status['active_tasks']:
        print(f"\n⚠️ 未完成题目: {', '.join(final_status['active_tasks'])}")

    print("="*80)
