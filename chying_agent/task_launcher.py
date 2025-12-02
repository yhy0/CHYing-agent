"""
任务启动器模块
==============

负责创建和启动解题任务：
- 任务创建
- LLM 对选择（角色互换）
- 历史记录传递
"""
import asyncio
from typing import Dict

from chying_agent.challenge_solver import solve_single_challenge
from chying_agent.common import log_system_event


async def start_challenge_task(
    challenge: Dict,
    retry_strategy,
    config,
    langfuse_handler,
    task_manager,
    concurrent_semaphore
) -> bool:
    """
    启动一个挑战任务

    Args:
        challenge: 题目信息
        retry_strategy: 重试策略
        config: 配置
        langfuse_handler: Langfuse 回调
        task_manager: 任务管理器
        concurrent_semaphore: 并发信号量

    Returns:
        True: 成功启动任务
        False: 任务已存在或已完成
    """
    challenge_code = challenge.get("challenge_code", "unknown")

    # ⭐ 修复：使用 await 调用异步方法（线程安全）
    # 检查是否已完成或正在执行
    if await task_manager.is_completed(challenge_code):
        return False

    if await task_manager.is_active(challenge_code):
        return False

    # ⭐ 获取重试次数和历史记录（线程安全）
    retry_count = await task_manager.get_retry_count(challenge_code)
    attempt_history = await task_manager.get_attempt_history(challenge_code)

    # ⭐ 根据重试次数选择 LLM 对（角色互换）
    main_llm, advisor_llm, strategy_desc = retry_strategy.get_llm_pair(retry_count)

    # 创建异步任务
    task = asyncio.create_task(
        solve_single_challenge(
            challenge=challenge,
            main_llm=main_llm,
            advisor_llm=advisor_llm,
            config=config,
            langfuse_handler=langfuse_handler,
            task_manager=task_manager,
            concurrent_semaphore=concurrent_semaphore,
            retry_strategy=retry_strategy,
            attempt_history=attempt_history,
            strategy_description=strategy_desc
        )
    )

    # 添加到任务管理器
    success = await task_manager.add_task(challenge_code, task)
    return success
