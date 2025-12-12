"""
单题解题逻辑模块
================

负责单个题目的解题流程：
- 自动侦察
- Agent 执行
- 结果处理
- 动态槽位填充
"""
import uuid
import time
import logging
import asyncio
from typing import Dict, Optional

from langfuse.langchain import CallbackHandler
from langfuse import get_client
from langchain_core.runnables import RunnableConfig
from langchain_core.messages import HumanMessage

from chying_agent.state import PenetrationTesterState
from chying_agent.graph import build_multi_agent_graph
from chying_agent.common import log_system_event
from chying_agent.retry_strategy import RetryStrategy


async def solve_single_challenge(
    challenge: Dict,
    main_llm,
    advisor_llm,
    config,
    langfuse_handler: Optional[CallbackHandler],  # 可选
    task_manager,  # ⭐ 新增：任务管理器
    concurrent_semaphore,  # ⭐ 新增：并发信号量
    retry_strategy: Optional[RetryStrategy] = None,  # ⭐ 新增：重试策略
    attempt_history: Optional[list] = None,  # ⭐ 新增：历史尝试记录
    strategy_description: str = "DeepSeek (主) + MiniMax (顾问)",  # ⭐ 新增：策略描述
    langfuse_metadata: Optional[Dict] = None  # ⭐ 新增：Langfuse 元数据
) -> Dict:
    """
    解决单个题目（完全异常隔离，单题失败不影响其他题）

    Args:
        challenge: 题目信息
        main_llm: 主 LLM
        advisor_llm: 顾问 LLM
        config: 配置
        langfuse_handler: Langfuse 回调
        task_manager: 任务管理器
        retry_strategy: 重试策略（可选）
        attempt_history: 历史尝试记录（可选）
        strategy_description: 策略描述

    Returns:
        解题结果 {code, flag, score, attempts, success}

    CRITICAL: 此函数保证任何异常都不会向外传播，始终返回结果字典
    """
    challenge_code = challenge.get("challenge_code", "unknown")
    difficulty = challenge.get("difficulty", "unknown")
    points = challenge.get("points", 0)

    # ⭐ 设置题目日志上下文（创建独立日志文件）
    from chying_agent.common import set_challenge_context, clear_challenge_context
    set_challenge_context(challenge_code)

    # ⭐ 设置当前题目的记忆隔离
    try:
        from chying_agent.tools.memory_tools import set_current_challenge
        set_current_challenge(challenge_code)
    except Exception as e:
        log_system_event(
            f"[记忆] ⚠️ 设置题目记忆隔离失败: {str(e)}",
            level=logging.WARNING
        )

    # 获取当前任务管理器状态
    status = await task_manager.get_status()

    log_system_event(
        f"[解题] 开始攻击: {challenge_code}",
        {
            "difficulty": difficulty,
            "points": points,
            "strategy": strategy_description,
            "active_tasks": status['active_count'],
            "completed": status['completed_count']
        }
    )

    # ⭐ 使用 try-finally 确保上下文一定会被清除
    try:
        # 为每个题目创建独立的状态
        initial_state: PenetrationTesterState = {
            "challenges": [challenge],  # 只包含当前题目
            "current_challenge": challenge,  # 直接开始攻击
            "completed_challenges": [],
            "total_challenges": 1,
            "solved_count": 0,
            "unsolved_count": 1,
            "hint_used_count": 0,
            "attempts_count": 0,
            "current_score": 0,
            "start_time": time.time(),
            "current_phase": "competition",
            "flag": None,
            "is_finished": False,
            "action_history": [],
            "evidence_chain_ids": [],
            "current_snapshot_id": f"challenge_{challenge_code}",
            "last_node": "advisor",
            "advisor_suggestion": None,
            # 智能路由控制字段
            "consecutive_failures": 0,
            "last_action_type": None,
            "request_advisor_help": False,
            "last_advisor_at_failures": 0,
            # 三层架构任务分发字段（V2 架构）
            "pending_task": None,
            "pending_flag": None,
        }

        # ==================== 自动信息收集（在 Agent 启动前） ====================
        target_info = challenge.get("target_info", {})
        target_ip = target_info.get("ip")
        target_ports = target_info.get("port", [])

        messages_to_inject = []

        # ⭐ 0. 自动获取提示（在所有信息收集之前）
        # ⭐ 手动模式跳过 API 调用
        is_manual_mode = challenge.get("_manual_mode", False)

        if is_manual_mode:
            log_system_event(
                f"[手动模式] 跳过自动获取提示（无 API）",
                {"challenge_code": challenge_code}
            )
        else:
            try:
                from chying_agent.tools.competition_api_tools import CompetitionAPIClient
                hint_client = CompetitionAPIClient()
                hint_data = hint_client.get_hint(challenge_code)

                hint_content = hint_data.get("hint_content", "")
                if hint_content:
                    messages_to_inject.append(
                        HumanMessage(content=f"💡 **官方提示**\n\n{hint_content}")
                    )
                    challenge["hint_content"] = hint_content
                    log_system_event(
                        f"[自动提示] ✅ 已获取提示: {challenge_code}",
                        {"hint_preview": hint_content[:100]}
                    )
            except Exception as hint_error:
                log_system_event(
                    f"[自动提示] ⚠️ 获取提示失败: {str(hint_error)}",
                    level=logging.WARNING
                )

        # ⭐ 消息注入顺序设计说明：
        #
        # 注入顺序：[自动侦察结果] → [历史尝试记录]
        #
        # 设计理由：
        # 1. **自动侦察优先**：让 Agent 首先看到最新的目标信息（HTML、响应头等）
        #    - 这是每次重试都会执行的新鲜数据
        #    - 帮助 Agent 快速了解目标状态
        #
        # 2. **历史记录在后**：在新信息之后提供历史失败经验
        #    - 避免 Agent 被历史失败方法先入为主
        #    - 鼓励 Agent 基于新侦察结果思考新方法
        #    - 历史记录作为"避坑指南"而非主导思路
        #
        # 3. **失败处理**：即使侦察失败，也会注入失败信息
        #    - 让 Agent 知道自动侦察尝试过但失败了
        #    - 提示 Agent 需要手动收集信息
        #
        # 注意：LangGraph 的消息顺序会影响 LLM 的注意力分配，
        #       最新的消息通常会获得更多关注。

        # ⭐ 1. 自动侦察（优先注入）
        if target_ip and target_ports:
            # ⭐ 修复：对所有端口进行侦察（支持多端口场景）
            ports_to_scan = target_ports if isinstance(target_ports, list) else [target_ports]
            
            log_system_event(
                f"[自动侦察] 开始收集目标信息: {target_ip}, challenge_code: {challenge_code}, ports: {ports_to_scan}",
                {}
            )

            try:
                from chying_agent.utils.recon import auto_recon_web_target, format_recon_result_for_llm

                # ⭐ 对每个端口进行侦察
                all_recon_summaries = []
                successful_ports = []
                failed_ports = []

                for target_port in ports_to_scan:
                    try:
                        # 执行自动侦察（提高超时时间到 30 秒）
                        recon_result = auto_recon_web_target(target_ip, target_port, timeout=30)

                        # 将侦察结果格式化
                        recon_summary = format_recon_result_for_llm(recon_result)
                        all_recon_summaries.append(
                            f"### 端口 {target_port}\n{recon_summary}"
                        )

                        successful_ports.append(target_port)
                        
                        log_system_event(
                            f"[自动侦察] ✅ 端口 {target_port} 信息收集完成",
                            {
                                "success": recon_result["success"],
                                "status_code": recon_result.get("status_code"),
                                "content_length": recon_result.get("html_length", 0)
                            }
                        )

                    except Exception as port_error:
                        failed_ports.append(target_port)
                        log_system_event(
                            f"[自动侦察] ⚠️ 端口 {target_port} 侦察失败: {str(port_error)}",
                            level=logging.WARNING
                        )
                        all_recon_summaries.append(
                            f"### 端口 {target_port}\n⚠️ 侦察失败: {str(port_error)}"
                        )

                # ⭐ 汇总所有端口的侦察结果
                if all_recon_summaries:
                    combined_summary = "\n\n".join(all_recon_summaries)
                    messages_to_inject.append(
                        HumanMessage(content=f"🔍 系统自动侦察结果：\n\n{combined_summary}")
                    )

                    # 记录到 action_history
                    initial_state["action_history"].append(
                        f"[自动侦察] 已扫描 {len(ports_to_scan)} 个端口：成功 {len(successful_ports)} 个，失败 {len(failed_ports)} 个"
                    )

                # ⭐ 如果全部端口都失败，额外提示
                if len(failed_ports) == len(ports_to_scan):
                    messages_to_inject.append(
                        HumanMessage(
                            content=f"⚠️ 所有端口自动侦察均失败\n\n"
                            f"建议: 请使用 execute_python_poc 或 execute_command 手动收集目标信息"
                        )
                    )

            except Exception as recon_error:
                log_system_event(
                    f"[自动侦察] ⚠️ 侦察模块异常: {str(recon_error)}",
                    level=logging.WARNING
                )
                # ⭐ 改进：侦察失败时也注入失败信息，让 Agent 知道需要手动收集
                messages_to_inject.append(
                    HumanMessage(
                        content=f"⚠️ 系统自动侦察失败\n\n"
                        f"错误信息: {str(recon_error)}\n\n"
                        f"建议: 请使用 execute_python_poc 或 execute_command 手动收集目标信息"
                    )
                )
                initial_state["action_history"].append(
                    f"[自动侦察] 侦察失败: {str(recon_error)}"
                )
        else:
            log_system_event(
                f"[自动侦察] ⚠️ 无法获取目标信息，跳过自动侦察",
                {"challenge": challenge},
                level=logging.WARNING
            )

        # ⭐ 2. 注入历史尝试记录（后注入，让 Agent 在新侦察结果后看到历史）
        if attempt_history and retry_strategy:
            history_summary = retry_strategy.format_attempt_history(attempt_history)
            if history_summary:
                messages_to_inject.append(
                    HumanMessage(content=f"📜 **历史尝试记录**\n\n{history_summary}")
                )
                log_system_event(
                    f"[解题] 注入历史记录",
                    {"attempts_count": len(attempt_history)}
                )

        # ⭐ 3. 将所有消息注入到初始状态
        if messages_to_inject:
            initial_state["messages"] = messages_to_inject

        # ==================== 自动信息收集结束 ====================

        # 构建独立的 Agent 图
        # 注意: build_multi_agent_graph 现在只接受 config 参数 (LangGraph Studio 兼容)
        # 但我们需要传入自定义的 LLM,所以需要创建一个包装函数
        from chying_agent.graph import build_multi_agent_graph_with_llms

        # 使用 challenge_code 作为图名称（用于 Langfuse trace name）
        app = await build_multi_agent_graph_with_llms(
            main_llm=main_llm,
            advisor_llm=advisor_llm,
            manual_mode=is_manual_mode,
            graph_name=challenge_code
        )

        # 配置运行参数
        from chying_agent.core.constants import AgentConfig

        thread_id = str(uuid.uuid4())
        recursion_limit = AgentConfig.get_recursion_limit()

        # 构建 RunnableConfig，包含 Langfuse 元数据
        runnable_config: RunnableConfig = {
            "configurable": {
                "thread_id": thread_id,
                "configuration": config.__dict__,
            },
            "callbacks": [langfuse_handler] if langfuse_handler else [],
            "recursion_limit": recursion_limit,
            # Langfuse: 通过 run_name 设置 trace name
            "run_name": challenge_code,
            # Langfuse 3.x: 通过 metadata 传递 session_id/tags
            "metadata": langfuse_metadata or {}
        }

        # 最外层异常保护：确保此函数永远不会抛出异常
        try:
            start_time = time.time()

            # ⭐ 执行 Agent（使用并发限制器 + 超时保护）
            task_timeout = AgentConfig.get_single_task_timeout()
            try:
                # ⭐ 修复：移除对私有属性 concurrent_semaphore._value 的访问
                # 避免重复读取环境变量，使用更稳定的方式
                async with concurrent_semaphore:
                    log_system_event(
                        f"[并发控制] 获取执行槽位: {challenge_code}",
                        {"状态": "已获取信号量"}
                    )

                    async with asyncio.timeout(task_timeout):
                        # ⭐ 使用 with_config 设置 run_name（Langfuse trace name）
                        final_state = await app.with_config({"run_name": challenge_code}).ainvoke(initial_state, runnable_config)
            except asyncio.TimeoutError:
                log_system_event(
                    f"[解题] ⏱️ 超时: {challenge_code}（{task_timeout}秒）",
                    level=logging.WARNING
                )

                # ⭐ 提取尝试摘要（即使超时也要记录）
                attempt_summary = retry_strategy.extract_attempt_summary(
                    initial_state, strategy_description
                ) if retry_strategy else None

                await task_manager.remove_task(challenge_code, success=False, attempt_summary=attempt_summary)
                return {
                    "code": challenge_code,
                    "flag": None,
                    "score": 0,
                    "attempts": 0,
                    "success": False,
                    "timeout": True,
                    "elapsed_time": task_timeout
                }
            except KeyboardInterrupt:
                # 允许用户手动中断
                log_system_event(
                    f"[解题] 🛑 用户中断: {challenge_code}",
                    level=logging.WARNING
                )
                raise  # KeyboardInterrupt 应该向上传播
            except Exception as agent_error:
                # Agent 执行异常（网络、API、LLM 错误等）
                import traceback
                error_traceback = traceback.format_exc()
                log_system_event(
                    f"[解题] ⚠️ Agent 执行异常: {challenge_code}",
                    {
                        "error_type": type(agent_error).__name__,
                        "error_message": str(agent_error),
                        "error_args": getattr(agent_error, 'args', None),
                        "initial_state_keys": list(initial_state.keys()) if initial_state else None,
                        "has_messages": "messages" in initial_state if initial_state else None,
                        "traceback": error_traceback
                    },
                    level=logging.ERROR
                )
                # 同时打印完整堆栈到控制台
                print(f"\n{'='*60}")
                print(f"[DEBUG] Agent 执行异常详情:")
                print(f"{'='*60}")
                print(f"错误类型: {type(agent_error).__name__}")
                print(f"错误信息: {str(agent_error)}")
                print(f"错误参数: {getattr(agent_error, 'args', None)}")
                print(f"initial_state 字段: {list(initial_state.keys()) if initial_state else 'None'}")
                print(f"是否包含 messages: {'messages' in initial_state if initial_state else 'N/A'}")
                print(f"\n完整堆栈追踪:")
                print(error_traceback)
                print(f"{'='*60}\n")
                await task_manager.remove_task(challenge_code, success=False)
                return {
                    "code": challenge_code,
                    "flag": None,
                    "score": 0,
                    "attempts": 0,
                    "success": False,
                    "error": f"agent_error: {str(agent_error)}",
                    "elapsed_time": time.time() - start_time
                }

            elapsed_time = time.time() - start_time
            flag = final_state.get("flag")
            attempts = len(final_state.get("action_history", []))

            # ⭐ 提取尝试摘要
            attempt_summary = retry_strategy.extract_attempt_summary(
                final_state, strategy_description
            ) if retry_strategy else None

            if flag:
                log_system_event(
                    f"[解题] ✅ 成功: {challenge_code}",
                    {
                        "flag": flag,
                        "attempts": attempts,
                        "elapsed": f"{elapsed_time:.1f}s",
                        "strategy": strategy_description
                    }
                )
                await task_manager.remove_task(challenge_code, success=True, attempt_summary=attempt_summary)
                return {
                    "code": challenge_code,
                    "flag": flag,
                    "score": points,  # 假设满分
                    "attempts": attempts,
                    "success": True,
                    "elapsed_time": elapsed_time
                }
            else:
                log_system_event(
                    f"[解题] ❌ 失败: {challenge_code}",
                    {
                        "attempts": attempts,
                        "elapsed": f"{elapsed_time:.1f}s",
                        "strategy": strategy_description
                    }
                )
                await task_manager.remove_task(challenge_code, success=False, attempt_summary=attempt_summary)
                return {
                    "code": challenge_code,
                    "flag": None,
                    "score": 0,
                    "attempts": attempts,
                    "success": False,
                    "elapsed_time": elapsed_time
                }

        except KeyboardInterrupt:
            # 允许 Ctrl+C 中断整个程序
            log_system_event(
                f"[解题] 🛑 用户中断",
                level=logging.WARNING
            )
            raise
        except Exception as outer_error:
            # 最外层兜底：捕获所有未预期的异常（包括 Agent 构建失败等）
            log_system_event(
                f"[解题] 🚨 严重异常: {challenge_code} - {str(outer_error)}",
                level=logging.CRITICAL
            )
            await task_manager.remove_task(challenge_code, success=False)
            return {
                "code": challenge_code,
                "flag": None,
                "score": 0,
                "attempts": 0,
                "success": False,
                "error": f"critical_error: {str(outer_error)}",
                "elapsed_time": 0
            }
    finally:
        # ⭐ 确保清除题目上下文（无论成功、失败还是异常）
        clear_challenge_context()
