"""
多 Agent 协作图（CTF 团队模拟）
=====================================

模拟真实 CTF 团队协作：
- Advisor Agent (MiniMax)：提供攻击建议和思路
- Main Agent (DeepSeek)：综合建议，做出决策并执行

架构：
┌──────────────┐
│ Main Agent   │  ← DeepSeek 主导决策和工具调用
└──────┬───────┘
       │ 参考建议
       ▼
┌──────────────┐
│ Advisor      │  ← MiniMax 提供不同视角的建议
└──────────────┘

作者：CHYing
日期：2025-11-09
"""
import asyncio
import time
import os
import logging
from typing import Literal
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage, ToolMessage
from langchain_core.runnables import RunnableConfig

from sentinel_agent.state import PenetrationTesterState
from sentinel_agent.tools import get_all_tools
from sentinel_agent.common import log_system_event, log_agent_thought
from sentinel_agent.langmem_memory import get_memory_store, get_all_memory_tools
from sentinel_agent.utils.rate_limiter import get_rate_limiter
from sentinel_agent.utils.util import retry_llm_call
from sentinel_agent.utils.failure_detector import detect_failure_with_llm

from sentinel_agent.prompts_book import (
    ADVISOR_SYSTEM_PROMPT,
    TOOL_OUTPUT_SUMMARY_PROMPT
)


# ==================== 初始化全局速率限制器 ====================
# 根据环境变量配置，默认每秒 2 个请求，最多 5 个突发请求
DEEPSEEK_RPS = float(os.getenv("DEEPSEEK_REQUESTS_PER_SECOND", "2.0"))
MINIMAX_RPS = float(os.getenv("MINIMAX_REQUESTS_PER_SECOND", "2.0"))

deepseek_limiter = get_rate_limiter("deepseek_llm", requests_per_second=DEEPSEEK_RPS, burst_size=5)
minimax_limiter = get_rate_limiter("minimax_llm", requests_per_second=MINIMAX_RPS, burst_size=5)




async def build_multi_agent_graph(
    main_llm: BaseChatModel,
    advisor_llm: BaseChatModel
):
    """
    构建多 Agent 协作图
    
    Args:
        main_llm: 主 Agent 的 LLM（DeepSeek）
        advisor_llm: 顾问 Agent 的 LLM（MiniMax）
        
    Returns:
        编译后的 LangGraph 应用
    """
    # 我的锅， 之前优化新增记忆模块时，claude 给我自己实现的，忘记 submit_flag 工具是这里管理的，我直接给删了，服了导致今天提交都有问题
    # 还是 v3 版本生效才解出几道题，不然今天一道题不会提交
    # ==================== 1. 初始化记忆系统 ====================
    memory_store = get_memory_store()
    memory_tools = get_all_memory_tools()
    
    # ==================== 2. 获取所有工具 ====================
    pentest_tools = get_all_tools()
    all_tools = pentest_tools + memory_tools

    log_system_event(
        f"--- 初始化多 Agent 协作系统 ---\n {all_tools}", 
        {
            "main_llm": type(main_llm).__name__,
            "advisor_llm": type(advisor_llm).__name__,
            "memory_tools_count": len(memory_tools),
        }
    )
    
    # 只有主 Agent 绑定工具
    main_llm_with_tools = main_llm.bind_tools(all_tools)
    # 顾问 Agent 不绑定工具（只提供建议）
    
    # ==================== 3. 创建自定义 ToolNode（带状态更新）====================
    base_tool_node = ToolNode(all_tools)

    # ⭐ 新增：工具输出总结函数
    async def summarize_tool_output(
        tool_output: str,
        tool_name: str = "unknown",
        llm: BaseChatModel = None
    ) -> str:
        """
        使用 LLM 总结工具输出

        Args:
            tool_output: 原始工具输出
            tool_name: 工具名称（用于日志）
            llm: 用于总结的 LLM（默认使用 main_llm）

        Returns:
            总结后的输出

        ⭐ 优化策略：
        - 输入 > 20000 字符：先截断到 20000，再总结
        - 总结失败：回退到智能截断（10000 字符）
        """
        if llm is None:
            llm = main_llm

        # ⭐ 新增：如果输入过长，先截断再总结（避免超过 LLM 输入限制）
        MAX_SUMMARY_INPUT = 20000  # LLM 总结的最大输入长度
        original_length = len(tool_output)

        if original_length > MAX_SUMMARY_INPUT:
            log_system_event(
                f"[工具总结] ⚠️ 输入过长，先截断再总结",
                {
                    "original_length": original_length,
                    "truncated_to": MAX_SUMMARY_INPUT,
                    "tool": tool_name
                },
                level=logging.WARNING
            )
            # 使用智能截断
            tool_output = _smart_truncate_output(tool_output, max_len=MAX_SUMMARY_INPUT)

        # 构建总结提示
        summary_prompt = f"{TOOL_OUTPUT_SUMMARY_PROMPT}\n\n```\n{tool_output}\n```"

        try:
            log_system_event(
                f"[工具总结] 开始总结 {tool_name} 的输出",
                {
                    "original_length": original_length,
                    "input_length": len(tool_output),
                    "tool": tool_name
                }
            )

            # 调用 LLM 进行总结（使用速率限制）
            response = await retry_llm_call(
                llm.ainvoke,
                [HumanMessage(content=summary_prompt)],
                limiter=deepseek_limiter,
                max_retries=3
            )

            summary = response.content

            log_system_event(
                f"[工具总结] ✅ 总结完成",
                {
                    "original_length": original_length,
                    "summary_length": len(summary),
                    "compression_ratio": f"{len(summary) / original_length * 100:.1f}%"
                }
            )

            return summary

        except Exception as e:
            log_system_event(
                f"[工具总结] ⚠️ 总结失败，返回智能截断版本",
                {"error": str(e)},
                level=logging.WARNING
            )
            # 回退到智能截断（使用原始输出，不是已截断的版本）
            return _smart_truncate_output(tool_output, max_len=10000)

    async def tool_node(state: PenetrationTesterState):
        """
        自定义工具节点：执行工具后检查是否需要更新状态

        关键功能：
        1. 执行工具调用
        2. 检查 submit_flag 结果，自动设置 flag 和 is_finished
        3. ⭐ 追踪失败次数（用于智能路由）
        4. 让并发任务在解决题目后立即退出
        5. ⭐ 自动注入 challenge_code 到 submit_flag 调用
        """

        # 是我傻逼了,错怪人家了 ~服了 题做出来了，但是调用 submit_flag 参数没有传入题目名字, 上次修改~
        # ⭐ 新增：在执行工具前，检查并自动补充 submit_flag 的 challenge_code 参数
        messages = state.get("messages", [])
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                # 遍历所有工具调用
                for tool_call in last_message.tool_calls:
                    if tool_call.get("name") == "submit_flag":
                        args = tool_call.get("args", {})
                        # 检查是否缺少 challenge_code 参数
                        if "challenge_code" not in args or not args.get("challenge_code"):
                            # 从 state 中获取当前题目代码
                            current_challenge = state.get("current_challenge")
                            if current_challenge:
                                challenge_code = current_challenge.get("challenge_code")
                                if not challenge_code:
                                    challenge_code = current_challenge.get("code")
                                # 自动注入 challenge_code
                                tool_call["args"]["challenge_code"] = challenge_code

                                log_system_event(
                                    "[自动注入] submit_flag 缺少 challenge_code，已自动补充",
                                    {
                                        "challenge_code": challenge_code,
                                        "flag": args.get("flag", "")[:50] + "..."
                                    }
                                )
                            else:
                                log_system_event(
                                    "[自动注入] ⚠️ 无法获取 challenge_code，submit_flag 可能失败",
                                    {"current_challenge": current_challenge},
                                    level=logging.WARNING
                                )

        # 执行基础工具调用
        result = await base_tool_node.ainvoke(state)

        # ⭐ 修复：提前获取 state 中的 messages，避免变量作用域错误
        messages = state.get("messages", [])

        # 是我傻逼了,错怪人家了 ~梅开二度，日了，下午的题又是这样，傻逼 Kimi ,上午是少一个参数，下午就意识不到调用 submit_flag ，一直尝试执行命令，智障~
        # ⭐ 新增：自动 FLAG 提取和提交机制（兜底策略）
        # 如果 LLM 找到了 FLAG 但没有正确调用 submit_flag，自动帮它提交
        auto_submit_enabled = os.getenv("AUTO_SUBMIT_FLAG", "true").lower() == "true"
        if auto_submit_enabled and "messages" in result:
            from sentinel_agent.utils.flag_validator import extract_flag_from_text
            from sentinel_agent.tools.competition_api_tools import get_api_client

            # 检查工具输出中是否包含 FLAG
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    # 提取所有可能的 FLAG
                    flags = extract_flag_from_text(msg.content)

                    if flags:
                        # 获取当前题目代码
                        current_challenge = state.get("current_challenge")
                        if current_challenge:
                            challenge_code = current_challenge.get("challenge_code") or current_challenge.get("code")

                            # 检查是否已经调用了 submit_flag（避免重复提交）
                            already_submitted = False
                            if messages:
                                last_message = messages[-1]
                                if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                                    for tool_call in last_message.tool_calls:
                                        if tool_call.get("name") == "submit_flag":
                                            already_submitted = True
                                            break

                            if not already_submitted:
                                try:
                                    # LLM 没有调用 submit_flag，自动提交第一个 FLAG
                                    flag_to_submit = flags[0]

                                    log_system_event(
                                        "[自动提交] 🤖 检测到 FLAG 但 LLM 未调用 submit_flag，自动提交",
                                        {
                                            "challenge_code": challenge_code,
                                            "flag": flag_to_submit,
                                            "total_flags_found": len(flags)
                                        }
                                    )
                                    # 直接调用 API 提交
                                    client = get_api_client()
                                    submit_result = client.submit_answer(challenge_code, flag_to_submit)

                                    if submit_result.get("correct"):
                                        # 提交成功！
                                        log_system_event(
                                            "[自动提交] ✅ FLAG 提交成功！",
                                            {
                                                "flag": flag_to_submit,
                                                "earned_points": submit_result.get("earned_points", 0)
                                            }
                                        )

                                        # 更新状态：设置 flag 和 is_finished
                                        result["flag"] = flag_to_submit
                                        result["is_finished"] = True
                                        # ⭐ 重置失败计数
                                        result["consecutive_failures"] = 0
                                        # ⭐ 立即返回，跳过后续失败检测
                                        return result
                                except Exception as e:
                                    log_system_event(
                                        "[自动提交] ⚠️ 自动提交失败",
                                        {"error": str(e)},
                                        level=logging.WARNING
                                    )

        # ⭐ 新增：检查工具输出长度，必要时进行总结
        # 从环境变量读取配置
        enable_summary = os.getenv("ENABLE_TOOL_SUMMARY", "true").lower() == "true"
        summary_threshold = int(os.getenv("TOOL_SUMMARY_THRESHOLD", "5000"))
        # ⭐ 新增：超过此阈值直接截断，不再总结（避免浪费 token）
        max_summary_length = int(os.getenv("MAX_SUMMARY_LENGTH", "10000"))

        if enable_summary and "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    original_length = len(msg.content)

                    # 如果输出超过阈值，进行总结或截断
                    if original_length > summary_threshold:
                        # 获取工具名称
                        tool_name = "unknown"
                        if messages and hasattr(messages[-1], "tool_calls") and messages[-1].tool_calls:
                            tool_name = messages[-1].tool_calls[0].get("name", "unknown")

                        # ⭐ 优化：如果输出超过 max_summary_length，直接截断，不再总结
                        if original_length > max_summary_length:
                            log_system_event(
                                f"[工具输出] 输出过长，直接截断（不总结）",
                                {
                                    "tool": tool_name,
                                    "original_length": original_length,
                                    "max_summary_length": max_summary_length
                                }
                            )
                            # 直接使用智能截断
                            msg.content = _smart_truncate_output(msg.content, max_len=max_summary_length)
                        else:
                            # 输出在 summary_threshold 和 max_summary_length 之间，使用 LLM 总结
                            log_system_event(
                                f"[工具输出] 检测到长输出，准备总结",
                                {
                                    "tool": tool_name,
                                    "original_length": original_length,
                                    "threshold": summary_threshold
                                }
                            )

                            # 调用总结函数
                            summary = await summarize_tool_output(
                                tool_output=msg.content,
                                tool_name=tool_name,
                                llm=main_llm
                            )

                            # 替换原始输出为总结
                            msg.content = summary

        # ⭐ 获取本次执行的工具类型（用于智能路由）
        # ⭐ 修复：messages 已在函数开头定义，无需重复获取
        current_action_type = None
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                # 记录第一个工具调用的名称
                current_action_type = last_message.tool_calls[0].get("name")
        
        # ⭐ 分析本次执行是否失败（用于智能路由）
        is_failure = False
        failure_reason = ""
        key_info = ""  # ⭐ 新增：保存关键信息摘要（用于 action_history）

        # 从环境变量读取配置
        enable_smart_detection = os.getenv("ENABLE_SMART_FAILURE_DETECTION", "true").lower() == "true"

        # 检查工具执行结果
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    content = msg.content

                    # 1. 优先检测答案正确的标记（成功）
                    if "答案正确" in content or "答案正确！获得" in content:
                        # 从工具调用参数中提取 flag
                        if messages:
                            last_message = messages[-1]
                            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                                for tool_call in last_message.tool_calls:
                                    if tool_call.get("name") == "submit_flag":
                                        submitted_flag = tool_call.get("args", {}).get("flag")
                                        if submitted_flag:
                                            log_system_event(
                                                f"[✅] 题目已解决！自动设置退出标志",
                                                {"flag": submitted_flag}
                                            )
                                            # 更新状态：设置 flag 和 is_finished
                                            result["flag"] = submitted_flag
                                            result["is_finished"] = True
                                            # ⭐ 重置失败计数
                                            result["consecutive_failures"] = 0
                                            # ⭐ 立即返回，跳过后续失败检测
                                            return result

                    # 2. ⭐ 使用智能失败检测（同时提取关键信息）
                    else:
                        if enable_smart_detection:
                            # 使用 LLM 语义判断（返回三元组：失败状态、原因、关键信息）
                            is_failure, failure_reason, key_info = await detect_failure_with_llm(
                                tool_output=content,
                                tool_name=current_action_type or "unknown",
                                llm=main_llm,
                                limiter=deepseek_limiter
                            )
                            
                            # ⭐ 关键改进：将提取的关键信息注入到工具输出中
                            # 这样 Agent 可以看到结构化的关键信息，而不是完全黑盒
                            if key_info:
                                # 在原始输出后追加分析摘要
                                analysis_summary = f"\n\n{'---'}\n[🤖 智能分析摘要]\n{key_info}\n{'---'}"
                                msg.content = msg.content + analysis_summary
                                
                                log_system_event(
                                    f"[关键信息注入] 已将分析结果注入到消息流",
                                    {
                                        "tool": current_action_type,
                                        "status": "失败" if is_failure else "成功",
                                        "key_info_length": len(key_info)
                                    }
                                )
                        else:
                            # 回退到关键字检测
                            failure_keywords = [
                                "error", "failed", "exception", "无法", "错误", "失败",
                                "not found", "denied", "incorrect", "unauthorized",
                                "alert-danger", "not authenticated", "invalid credentials"
                            ]
                            is_failure = any(kw in content.lower() for kw in failure_keywords)
                            failure_reason = "关键字匹配检测" if is_failure else ""
        
        # ⭐ 更新失败计数和操作类型（用于智能路由）
        consecutive_failures = state.get("consecutive_failures", 0)

        if is_failure:
            # ⭐ 修复：任何失败都累加，不再检查操作类型
            # 原逻辑问题：只有同类型工具连续失败才累加，导致 Advisor 很难被触发
            # 新逻辑：任何连续失败都累加，更容易触发 Advisor 介入
            consecutive_failures += 1

            log_system_event(
                f"[智能路由] 检测到失败，连续失败次数: {consecutive_failures}",
                {
                    "action_type": current_action_type,
                    "failure_reason": failure_reason
                }
            )
        else:
            # 成功或无明显错误，重置计数
            consecutive_failures = 0

        result["consecutive_failures"] = consecutive_failures
        result["last_action_type"] = current_action_type

        # ⭐ 新增：记录操作历史到 action_history（供 Advisor 参考）
        if current_action_type:
            # 提取工具调用的参数（用于更详细的记录）
            tool_args_summary = ""
            if messages:
                last_message = messages[-1]
                if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                    for tool_call in last_message.tool_calls:
                        if tool_call.get("name") == current_action_type:
                            args = tool_call.get("args", {})
                            # ⭐ 统一格式：工具名 + 关键信息
                            if current_action_type == "submit_flag":
                                flag = args.get("flag", "")
                                tool_args_summary = f"提交 FLAG: {flag[:30]}..."
                            elif current_action_type == "execute_command":
                                cmd = args.get("command", "")
                                tool_args_summary = f"执行命令: {cmd[:50]}..."
                            elif current_action_type == "execute_python_poc":
                                code_preview = args.get("code", "")[:50].replace("\n", " ")
                                tool_args_summary = f"执行 Python: {code_preview}..."
                            else:
                                # 其他工具：显示关键信息
                                tool_args_summary = f"信息: {key_info[:100]}" if key_info else ""
                            break

            # 构建操作记录（统一格式）
            status_emoji = "❌" if is_failure else "✅"
            if tool_args_summary:
                action_record = f"{status_emoji} [{current_action_type}] {tool_args_summary} → {failure_reason if is_failure else '成功'}"
            else:
                action_record = f"{status_emoji} [{current_action_type}] → {failure_reason if is_failure else '成功'}"

            # 添加到 action_history（使用 add 合并）
            result["action_history"] = [action_record]

            log_system_event(
                f"[操作历史] 记录到 action_history",
                {
                    "action": current_action_type,
                    "status": "失败" if is_failure else "成功",
                    "record": action_record
                }
            )

        # ⭐ 消息压缩已在 state.py 的 compress_messages 函数中自动处理
        # 无需在此手动压缩，LangGraph 会自动调用 reduce 函数

        return result
    
    # ==================== 4. 定义 Advisor Agent 节点 ====================
    async def advisor_node(state: PenetrationTesterState):
        """
        顾问 Agent - 提供攻击建议
        
        特点：
        - 不调用工具，只提供文字建议
        - 分析主 Agent 的历史行动，提供新视角
        - 简洁明了的输出
        """
        # ⭐ 修复：移除有 bug 的逻辑
        # 原始问题：如果 advisor_suggestion 存在但 last_action_output 被清空，
        # 就会跳过咨询，导致无法重新获取建议
        # 新策略：直接进行咨询，由路由逻辑决定是否需要新的建议
        
        hin_content_sys = ""
        target_info_msg = ""
        if state.get("current_challenge"):
            challenge = state["current_challenge"]
            hin_content_sys = challenge.get("hint_content", "")  # ⭐ 提取 hint 内容
            target_info = challenge.get("target_info", {})
            ip = target_info.get("ip", "unknown")
            ports = target_info.get("port", [])
            target_info_msg = f"- **目标**: {ip}:{','.join(map(str, ports))}"
        # 构建顾问的上下文
        advisor_sys_prompt  = ADVISOR_SYSTEM_PROMPT
        if hin_content_sys != "":
            advisor_sys_prompt = ADVISOR_SYSTEM_PROMPT + f"\n## 目标##\n{target_info_msg}\n## 题目提示(**非常重要**): \n\n{hin_content_sys}\n\n"
        advisor_messages = [SystemMessage(content=advisor_sys_prompt)]
        
        # 构建动态提示词
        context_parts = []

        # ⭐ 0. 提取自动侦察结果（如果存在）
        messages = state.get("messages", [])
        recon_info = None
        if messages:
            # 检查第一条消息是否是自动侦察结果
            first_msg = messages[0]
            if hasattr(first_msg, 'content') and "🔍 系统自动侦察结果" in first_msg.content:
                recon_info = first_msg.content

        if recon_info:
            context_parts.append(f"""
## 🔍 自动侦察结果

{recon_info}
""")

        # 1. 比赛状态总览
        current_phase = state.get("current_phase", "unknown")
        current_score = state.get("current_score", 0)
        solved_count = state.get("solved_count", 0)
        total_challenges = state.get("total_challenges", 0)
        start_time = state.get("start_time")
        
        if total_challenges > 0:
            elapsed_time = ""
            if start_time:
                import time
                elapsed_seconds = int(time.time() - start_time)
                elapsed_time = f"{elapsed_seconds // 60}分{elapsed_seconds % 60}秒"
            
        
        # 2. 当前题目信息
        if state.get("current_challenge"):
            challenge = state["current_challenge"]

            # 计算实际尝试次数：统计有工具调用的消息数量
            messages = state.get("messages", [])
            attempts = len([m for m in messages if hasattr(m, 'tool_calls') and m.tool_calls])
            
            # 提取题目信息
            code = challenge.get("challenge_code", challenge.get("code", "unknown"))
            difficulty = challenge.get("difficulty", "unknown")
            points = challenge.get("points", 0)
            hint_viewed = challenge.get("hint_viewed", False)
            hint_content = challenge.get("hint_content", "")  # ⭐ 提取 hint 内容
            target_info = challenge.get("target_info", {})
            ip = target_info.get("ip", "unknown")
            ports = target_info.get("port", [])
            
            # ⭐ 构建提示信息（如果存在）
            hint_section = ""
            if hint_content:
                hint_section = f"""
- **💡 官方提示（重要！）**: {hint_content}
  **⚠️ 这是出题人给出的关键线索，请务必深入分析！**"""
            
            context_parts.append(f"""
## 🎯 当前攻击目标

- **题目代码**: {code}
- **目标**: {ip}:{','.join(map(str, ports))}
- **已尝试次数**: {attempts}
- **提示状态**: {"已查看（得分会扣除惩罚分）" if hint_viewed else "未查看"}{hint_section}
""")
        
        # 3. 历史操作
        action_history = state.get('action_history', [])
        if action_history:
            context_parts.append(f"""
## 📜 主攻击手的历史操作

{_format_action_history(action_history)}
""")

        # 5. 已发现的信息（从记忆工具读取）
        try:
            from sentinel_agent.tools.memory_tools import get_all_discoveries

            # ⭐ 线程安全改进：显式传递 challenge_code，避免多线程环境下的记忆串题
            current_challenge = state.get("current_challenge")
            if current_challenge:
                challenge_code = current_challenge.get("challenge_code", current_challenge.get("code"))

                # 读取主攻击手记录的所有记忆（显式传递 challenge_code）
                memories = get_all_discoveries(challenge_code=challenge_code)

                if memories:
                    memory_lines = []
                    for m in memories:
                        content = m.get('content', '')
                        memory_lines.append(f"- {content}")

                    context_parts.append(f"""
## 🔐 主攻击手的记忆

{chr(10).join(memory_lines)}
""")

                    log_system_event(
                        f"[Advisor] 读取到 {len(memories)} 条记忆",
                        {"challenge_code": challenge_code, "memory_count": len(memories)}
                    )
            else:
                log_system_event(
                    "[Advisor] ⚠️ 当前没有活跃题目，跳过记忆读取",
                    level=logging.WARNING
                )
        except Exception as e:
            # 异常处理：即使读取失败也不影响 Advisor 运行
            log_system_event(
                f"[Advisor] ⚠️ 读取记忆工具失败: {str(e)}",
                level=logging.WARNING
            )
        
        # 组合所有上下文
        if context_parts:
            full_context = "\n".join(context_parts) + "\n\n---\n\n请基于以上信息，提供你的攻击建议。"
            advisor_messages.append(HumanMessage(content=full_context))
        else:
            # 初始状态但无题目信息（理论上不应出现，因为题目已预加载）
            advisor_messages.append(HumanMessage(content="""
主攻击手尚未选择题目或开始攻击。请等待进一步信息。
"""))
        
        log_agent_thought("[Advisor] 开始分析...")
        
        # ⭐ 调用顾问 LLM（带重试和速率限制）
        try:
            advisor_response: AIMessage = await retry_llm_call(
                advisor_llm.ainvoke,
                advisor_messages,
                max_retries=5,
                base_delay=2.0,
                limiter=minimax_limiter  # ⭐ 添加：MiniMax 速率限制
            )
        except Exception as e:
            # LLM 调用失败后的降级处理
            log_system_event(
                "[Advisor] ❌ LLM 调用失败，跳过本次建议",
                {"error": str(e)},
                level=logging.ERROR
            )
            # 返回空建议，让 Main Agent 自主决策
            return {
                "advisor_suggestion": "",
                "messages": [],
                "last_action_output": ""
            }
        
        log_agent_thought(
            "[MiniMax] 提供建议",
            {"advice": advisor_response.content}
        )
        
        # 将建议存入状态（供主 Agent 参考）
        return {
            "advisor_suggestion": advisor_response.content,
            "messages": [],  # 不添加到主消息流
            "last_action_output": ""  # 清空输出，标记建议已生成
        }
    
    # ==================== 5. 定义 Main Agent 节点 ====================
    async def main_agent_node(state: PenetrationTesterState):
        """
        主 Agent - 综合建议，做出决策并执行
        
        特点：
        - 参考顾问的建议
        - 调用工具执行攻击
        - 最终决策权在主 Agent
        """
        # 构建主 Agent 的系统提示词
        # ⭐ 修复：不要在这里添加 SYSTEM_PROMPT，让 _build_system_prompt 来添加
        # 避免 SYSTEM_PROMPT 重复出现两次
        system_prompt_parts = []
        
        # 如果有顾问建议，添加到系统提示词
        advisor_suggestion = state.get("advisor_suggestion")
        if advisor_suggestion:
            system_prompt_parts.append(f"""
---

**下面是顾问的建议，你应该深入分析和参考**
## 🤝 团队顾问的建议

{advisor_suggestion}

---

**决策参考**：
1. **评估建议**：分析顾问建议的合理性和可行性
2. **自主判断**：结合你自己的观察和经验，做出独立判断
3. **行动方案**：
   - 如果采纳：说明理由并执行
   - 如果不采纳：说明原因并提出你的替代方案
   - 如果部分采纳：说明哪些部分采纳，哪些部分调整
4. **避免空转**：本轮决策应包含具体行动（调用工具），而非仅思考

**记住**：顾问提供参考视角，但最终决策权在你。请综合双方观点，做出最优选择。
""")

        # 添加动态上下文（复用原有逻辑）
        system_message = _build_main_system_prompt(state, system_prompt_parts)
        
        # 获取对话历史
        # ⭐ 优化: 更激进的消息清理策略,避免上下文超限
        # 策略: 保留最近 10 条消息 + 自动侦察结果 (从 20 条降低到 10 条)
        messages = list(state.get("messages", []))

        # ⭐ 新增: 从环境变量读取配置,默认保留 10 条
        max_history_messages = int(os.getenv("MAX_HISTORY_MESSAGES", "10"))
        max_total_messages = max_history_messages + 1  # +1 for 侦察结果

        if len(messages) > max_total_messages:
            # 保留第一条(自动侦察)和最近 N 条
            messages = [messages[0]] + messages[-max_history_messages:]
            log_system_event(
                f"[上下文管理] 清理旧消息,保留 {len(messages)} 条",
                {"dropped": len(state.get("messages", [])) - len(messages), "max_history": max_history_messages}
            )

        # 添加或更新系统消息
        if not messages or not isinstance(messages[0], SystemMessage):
            messages.insert(0, system_message)
        else:
            messages[0] = system_message
        
        log_agent_thought(
            "[Main Agent (DeepSeek)] 开始决策...",
            {
                "has_advisor_suggestion": bool(advisor_suggestion),
                "attempts": len([m for m in state.get("messages", []) if hasattr(m, 'tool_calls') and m.tool_calls])
            }
        )
        
        # ⭐ 调用主 LLM（带重试和速率限制）
        try:
            ai_message: AIMessage = await retry_llm_call(
                main_llm_with_tools.ainvoke,
                messages,
                max_retries=5,
                base_delay=2.0,
                limiter=deepseek_limiter  # ⭐ 添加：DeepSeek 速率限制
            )
        except Exception as e:
            # LLM 调用失败后的降级处理
            log_system_event(
                "[Main Agent] ❌ LLM 调用失败，使用降级策略",
                {"error": str(e)},
                level=logging.ERROR
            )
            # 返回一个简单的错误消息，让路由决定下一步
            fallback_message = AIMessage(
                content=f"LLM 调用失败，错误：{str(e)}。请稍后重试或咨询 Advisor。[REQUEST_ADVISOR_HELP]"
            )
            return {
                "messages": [fallback_message],
                "advisor_suggestion": "",
                "request_advisor_help": True  # 触发 Advisor 介入
            }

        # 提取工具调用信息
        tool_calls = getattr(ai_message, 'tool_calls', [])

        # 记录决策内容（即使为空也记录，方便调试）
        content = ai_message.content or ""
        
        # ⭐ 检测主动求助标记
        request_help = "[REQUEST_ADVISOR_HELP]" in content
        if request_help:
            log_agent_thought("[Main Agent] 🆘 检测到主动求助标记，将咨询 Advisor")
        
        log_agent_thought(
            "[Main Agent (DeepSeek)] 决策内容",
            {
                "content": content if content else "（无文字输出，直接调用工具）",
                "has_tool_calls": bool(tool_calls),
                "tool_count": len(tool_calls) if tool_calls else 0,
                "request_help": request_help
            }
        )

        # 如果有工具调用，详细记录
        if tool_calls:
            log_agent_thought(
                f"[Main Agent (DeepSeek)]：调用 {len(tool_calls)} 个工具",
                {
                    "tools": [
                        {"name": tc.get("name"), "args": tc.get("args", {})}
                        for tc in tool_calls
                    ]
                }
            )

        # 清除已使用的顾问建议（避免重复触发）
        return {
            "messages": [ai_message],
            "advisor_suggestion": "",  # 清空建议，标记已使用
            "request_advisor_help": request_help  # ⭐ 设置求助标记
        }
    
    # ==================== 6. 定义路由函数 ====================
    def should_continue(state: PenetrationTesterState) -> Literal["advisor", "tools", "main_agent", "end"]:
        """
        路由逻辑（已优化）：
        1. 有工具调用 → tools
        2. ⭐ 优先检查是否找到 FLAG 或完成（避免工具执行后空转）
        3. 工具执行完 → advisor（获取新建议）
        4. 有顾问建议 → main_agent（主 Agent 决策）
        5. 超限 → end
        """
        messages = state.get("messages", [])
        
        if not messages:
            # 初始状态：先让顾问分析
            return "advisor"
        
        last_message = messages[-1]
        
        # 1. 检查是否有工具调用
        if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
            log_system_event(f"[Router] 主 Agent 调用工具 → ToolNode")
            return "tools"
        
        # ⭐ 2. 优先检查是否找到 FLAG 或任务完成（关键优化点）
        # 这个检查必须在 last_action_output 检查之前，避免工具执行成功后还要空转 2 次 LLM
        if state.get("flag"):
            log_system_event("[Router] ✅ 已找到 FLAG，任务完成")
            return "end"
        
        if state.get("is_finished"):
            log_system_event("[Router] ✅ 所有赛题已完成")
            return "end"
        
        # 3. 检查是否超限（从环境变量读取）
        # 计算实际尝试次数：统计有工具调用的消息数量
        messages = state.get("messages", [])
        attempts = len([m for m in messages if hasattr(m, 'tool_calls') and m.tool_calls])

        from sentinel_agent.core.constants import AgentConfig
        max_attempts = AgentConfig.get_max_attempts()

        if attempts > max_attempts:
            log_system_event(
                f"[Router] ⚠️ 尝试次数超过限制 ({attempts}/{max_attempts})，结束任务"
            )
            return "end"
        
        # 5. 有顾问建议且主 Agent 未使用 → 主 Agent 决策
        if state.get("advisor_suggestion"):
            log_system_event("[Router] 已有顾问建议 → 主 Agent 决策")
            return "main_agent"
        
        # 6. 默认：主 Agent 继续思考
        log_system_event("[Router] 主 Agent 继续思考")
        return "main_agent"
    
    # ==================== 7. 构建 StateGraph ====================
    workflow = StateGraph(PenetrationTesterState)
    
    # 添加节点
    workflow.add_node("advisor", advisor_node)
    workflow.add_node("main_agent", main_agent_node)
    workflow.add_node("tools", tool_node)
    
    # 设置入口：先咨询顾问
    workflow.set_entry_point("advisor")
    
    # 定义边
    workflow.add_conditional_edges(
        "advisor",
        lambda state: "main_agent",  # 顾问分析完 → 主 Agent
    )
    
    workflow.add_conditional_edges(
        "main_agent",
        should_continue,
        {
            "tools": "tools",
            "main_agent": "main_agent",
            "advisor": "advisor",
            "end": END
        }
    )
    
    # ⭐ 关键优化：智能路由 - 默认 Main Agent 连续作战，仅在必要时咨询 Advisor
    # 工具执行完后的路由逻辑
    def should_continue_after_tool(state: PenetrationTesterState) -> Literal["advisor", "main_agent", "end"]:
        """
        工具执行完后的智能路由逻辑
        
        策略：
        1. 优先检查是否完成（避免空转）
        2. 检查是否超限
        3. ⭐ 智能决策是否需要 Advisor：
           - 连续失败 >= 3 次 → 求助 Advisor
           - Main Agent 主动请求帮助 → 咨询 Advisor
           - 尝试次数达到关键节点（5、10、15 次）→ 咨询 Advisor
           - 否则 → 返回 Main Agent（允许连续攻击）
        """
        # 1. 优先检查是否完成
        if state.get("flag"):
            log_system_event("[Router-Tool] ✅ 工具执行后检测到 FLAG，直接结束")
            return "end"
        
        if state.get("is_finished"):
            log_system_event("[Router-Tool] ✅ 工具执行后检测到任务完成，直接结束")
            return "end"
        
        # 2. 检查是否超限
        messages = state.get("messages", [])
        attempts = len([m for m in messages if hasattr(m, 'tool_calls') and m.tool_calls])
        
        from sentinel_agent.core.constants import AgentConfig
        max_attempts = AgentConfig.get_max_attempts()
        
        if attempts > max_attempts:
            log_system_event(
                f"[Router-Tool] ⚠️ 工具执行后检测到超限 ({attempts}/{max_attempts})，直接结束"
            )
            return "end"
        
        # ⭐ 修复：使用常量替代硬编码的魔数，支持环境变量配置
        # ⭐ 3. 智能决策：是否需要 Advisor 介入
        consecutive_failures = state.get("consecutive_failures", 0)
        request_help = state.get("request_advisor_help", False)

        from sentinel_agent.core.constants import SmartRoutingConfig
        failures_threshold = SmartRoutingConfig.get_failures_threshold()
        consultation_interval = SmartRoutingConfig.get_consultation_interval()

        # ⭐ 修复：避免重复触发 Advisor（仅在首次达到阈值时触发）
        # 3.1 连续失败次数首次达到阈值 → 需要 Advisor 帮助
        # 原逻辑问题：consecutive_failures % failures_threshold == 0 会在 3, 6, 9... 次都触发
        # 新逻辑：仅在 3, 6, 9... 次（即阈值的倍数）触发，但通过状态标记避免重复
        if consecutive_failures > 0 and consecutive_failures % failures_threshold == 0:
            # 检查是否已经为这个失败次数咨询过 Advisor
            last_advisor_at_failures = state.get("last_advisor_at_failures", 0)
            if consecutive_failures != last_advisor_at_failures:
                log_system_event(
                    f"[智能路由] 🆘 连续失败 {consecutive_failures} 次（达到阈值倍数 {failures_threshold}），请求 Advisor 帮助",
                    {"action_type": state.get("last_action_type")}
                )
                # ⭐ 标记：已为这个失败次数咨询过 Advisor
                state["last_advisor_at_failures"] = consecutive_failures
                return "advisor"

        # 3.2 Main Agent 主动请求帮助
        if request_help:
            log_system_event("[智能路由] 🆘 Main Agent 主动请求 Advisor 帮助")
            return "advisor"

        # 3.3 关键节点检查（每隔 N 次尝试咨询一次 Advisor）
        if attempts > 0 and attempts % consultation_interval == 0:
            log_system_event(
                f"[智能路由] 🔄 达到关键节点（第 {attempts} 次尝试，间隔：{consultation_interval}），咨询 Advisor"
            )
            return "advisor"
        
        # 3.4 默认：返回 Main Agent（允许连续攻击）
        log_system_event(
            f"[智能路由] ⚡ 工具执行完毕 → 返回 Main Agent（连续攻击模式）",
            {
                "consecutive_failures": consecutive_failures,
                "attempts": attempts
            }
        )
        return "main_agent"
    
    workflow.add_conditional_edges(
        "tools",
        should_continue_after_tool,
        {
            "advisor": "advisor",
            "main_agent": "main_agent",  # ⭐ 允许直接返回 Main Agent（连续攻击）
            "end": END
        }
    )
    
    # ==================== 8. 编译图 ====================
    app = workflow.compile(store=memory_store)
    
    log_system_event("--- 多 Agent 协作图构建完成 ---")
    return app


# ==================== 辅助函数 ====================

def _smart_truncate_output(output: str, max_len: int = 10000) -> str:
    """
    智能截断输出（保留关键错误信息）
    
    策略：
    1. 优先保留错误信息（Error、Exception、Failed）
    2. 保留 HTML 标题和表单（<title>、<form>）
    3. 保留首尾各一半
    """
    if len(output) <= max_len:
        return output
    
    # 关键词检测
    error_keywords = ["error", "exception", "failed", "flag{", "FLAG{", "<title>", "<form", "sql", "xss"]
    
    # 查找关键信息的位置
    important_sections = []
    for keyword in error_keywords:
        idx = output.lower().find(keyword.lower())
        if idx != -1:
            # 提取关键词前后 200 字符
            start = max(0, idx - 100)
            end = min(len(output), idx + 100)
            important_sections.append((start, end))
    
    if important_sections:
        # 合并重叠区域
        important_sections.sort()
        merged = [important_sections[0]]
        for start, end in important_sections[1:]:
            if start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        
        # 拼接重要片段
        parts = []
        for start, end in merged[:3]:  # 最多 3 个片段
            parts.append(output[start:end])
        
        result = "\n...\n".join(parts)
        if len(result) > max_len:
            return result[:max_len] + "\n... (输出过长，已截断)"
        return result
    
    # 无关键信息：保留首尾
    half = max_len // 2
    return f"{output[:half]}\n... (中间省略 {len(output) - max_len} 字符) ...\n{output[-half:]}"



def _format_action_history(action_history: list) -> str:
    """格式化操作历史"""
    if not action_history:
        return "暂无操作历史"
    
    # 只显示最近 5 次
    recent = action_history[-10:]
    formatted = []
    for i, action in enumerate(recent, 1):
        formatted.append(f"{i}. {action}")
    
    return "\n".join(formatted)


def _build_main_system_prompt(state: PenetrationTesterState, base_parts: list) -> SystemMessage:
    """
    构建主 Agent 的动态系统提示词
    
    Args:
        state: 当前状态
        base_parts: 额外的提示词片段（如 Advisor 建议），会插入到 SYSTEM_PROMPT 和动态上下文之间
    
    Returns:
        SystemMessage 包含完整的系统提示词
    """
    # 获取完整的动态提示词（包含 SYSTEM_PROMPT + 动态上下文）
    original_prompt = _build_system_prompt(state)
    
    # 如果有额外的片段（如 Advisor 建议），插入到 SYSTEM_PROMPT 之后
    if base_parts:
        # 拼接顺序：SYSTEM_PROMPT + base_parts + 动态上下文
        combined = original_prompt.content + "\n\n" + "\n\n".join(base_parts)
    else:
        # 没有额外片段，直接返回原始提示词
        combined = original_prompt.content
    
    return SystemMessage(content=combined)

def _build_system_prompt(state: PenetrationTesterState) -> SystemMessage:
    """
    动态构建系统提示词（基于当前状态）
    
    这是 LangGraph 推荐的做法：
    - 通过动态提示词根据状态引导 LLM 行为
    - 而非创建多个节点来处理不同阶段
    
    Args:
        state: 当前状态
        
    Returns:
        SystemMessage 包含动态生成的系统提示词
    """
    from sentinel_agent.prompts import SYSTEM_PROMPT
    
    # 基础系统提示词
    prompt_parts = [SYSTEM_PROMPT]
    
    # --- 动态添加当前任务上下文 ---
    
    # 阶段 3: 正在攻击赛题
    if state.get("current_challenge"):
        challenge = state["current_challenge"]

        # 计算实际尝试次数：统计有工具调用的消息数量
        messages = state.get("messages", [])
        attempts = len([m for m in messages if hasattr(m, 'tool_calls') and m.tool_calls])

        code = challenge.get("challenge_code", challenge.get("code"))
        difficulty = challenge.get("difficulty", "unknown")
        points = challenge.get("points", 0)
        hint_viewed = challenge.get("hint_viewed", False)
        hint_content = challenge.get("hint_content", "")  # ⭐ 获取提示内容
        target_info = challenge.get("target_info", {})
        ip = target_info.get("ip", "unknown")
        ports = target_info.get("port", [])
        
        # 构建目标 URL（假设是 HTTP）
        port_str = str(ports[0]) if ports else "80"
        target_url = f"http://{ip}:{port_str}"
        
        # ⭐ 检查是否有自动侦察结果
        recon_hint = ""
        if messages:
            first_msg = messages[0]
            if hasattr(first_msg, 'content') and "🔍 系统自动侦察结果" in first_msg.content:
                recon_hint = "\n\n**💡 提示**：系统已自动完成初步侦察，请查看消息历史中的侦察结果，无需重复基础信息收集。"

        # ⭐ 构建提示信息（如果有提示内容）
        hint_section = ""
        if hint_content:
            hint_section = f"\n\n### 💡 **官方提示**\n**{hint_content}**\n\n**重要**: 请仔细阅读上述提示，**必须重点分析其含义和指向**，**它包含解题的关键线索**！\n\n**你应该根据官方提示制定策略**"

        prompt_parts.append(f"""
## 🎯 当前攻击中：{code}

### 赛题信息
- **代码**：`{code}`
- **难度**：{difficulty.upper()}
- **满分**：{points} 分
- **目标**：{target_url}
- **尝试次数**：{attempts}
- **提示状态**：{"已查看 💡（扣分）" if hint_viewed else "未查看"}{recon_hint}{hint_section}


### 攻击策略
1. **信息收集**：
   - 使用 `execute_python_poc` 执行 `requests.get('{target_url}')` 查看页面
   - 分析响应头、Cookie、隐藏字段
   
2. **漏洞测试**（根据类型）：
   - **SQL注入**：测试输入参数（`' OR '1'='1`）
   - **XSS**：测试输入输出（`<script>alert(1)</script>`）
   - **文件包含**：测试路径参数（`../../../../etc/passwd`）
   - **命令注入**：测试系统命令（`; ls -la`）
   
3. **利用工具选择**：
   - **简单单次请求**：`execute_command` + curl（如：GET 页面源码）
   - **需要登录/会话/多次请求**：直接使用 `execute_python_poc` + Python requests
     ```python
     import requests
     session = requests.Session()
     # 登录、保持会话、处理 Cookie...
     ```
   - **暴力破解/批量测试**：使用 `execute_python_poc` 编写循环逻辑
   - **复杂攻击链**：使用 `execute_python_poc` 编写完整 PoC
   
4. **提取 FLAG**：
   - FLAG 格式通常为 `flag{{...}}` 或 `FLAG{{...}}`
   - 找到后使用 `submit_flag` 提交
""")
        
        # ⭐ 检测失败模式并提供警告
        messages = state.get("messages", [])
        if len(messages) >= 10:
            # 提取最近的工具调用（仅检查有工具调用的消息）
            recent_tool_calls = []
            for msg in messages[-10:]:  # 检查最近 10 条消息
                if hasattr(msg, 'tool_calls') and msg.tool_calls:
                    for tc in msg.tool_calls:
                        # 构造工具调用的标识（工具名 + 参数）
                        tool_signature = f"{tc['name']}:{str(tc.get('args', {}))}"
                        recent_tool_calls.append(tool_signature)

            # ⭐ 检测 1: 完全相同的工具调用重复 5 次
            if len(recent_tool_calls) >= 5:
                from collections import Counter
                call_counts = Counter(recent_tool_calls[-5:])
                most_common_call, count = call_counts.most_common(1)[0]

                if count >= 5:
                    prompt_parts.append("""
### 🚨 系统警告：检测到重复操作
- 已连续 5 次执行完全相同的操作但持续失败
- 建议：尝试完全不同的攻击思路或工具
- 提示：如果某个方法失败了,继续重复不会产生不同结果
""")

            # ⭐ 检测 2: 工具调用错误重复 5 次（检查消息内容中的错误模式）
            recent_errors = []
            for msg in messages[-10:]:
                if hasattr(msg, 'content') and msg.content:
                    content_lower = str(msg.content).lower()
                    # 识别常见错误模式
                    if 'error' in content_lower or 'exception' in content_lower:
                        # 提取错误类型（简化的启发式方法）
                        if '400' in content_lower or 'bad request' in content_lower:
                            recent_errors.append('HTTP_400')
                        elif '401' in content_lower or 'unauthorized' in content_lower:
                            recent_errors.append('HTTP_401')
                        elif '403' in content_lower or 'forbidden' in content_lower:
                            recent_errors.append('HTTP_403')
                        elif '404' in content_lower or 'not found' in content_lower:
                            recent_errors.append('HTTP_404')
                        elif '500' in content_lower or 'internal server error' in content_lower:
                            recent_errors.append('HTTP_500')
                        elif 'timeout' in content_lower or 'timed out' in content_lower:
                            recent_errors.append('TIMEOUT')
                        elif 'connection' in content_lower and ('refused' in content_lower or 'failed' in content_lower):
                            recent_errors.append('CONNECTION_ERROR')
                        else:
                            recent_errors.append('UNKNOWN_ERROR')

            # 如果最近 5 条消息中有相同错误重复出现
            if len(recent_errors) >= 5:
                from collections import Counter
                error_counts = Counter(recent_errors[-5:])
                most_common_error, error_count = error_counts.most_common(1)[0]

                if error_count >= 5:
                    prompt_parts.append(f"""
### 🚨 系统警告：检测到重复错误
- 已连续 5 次遇到相同类型的错误
- 错误类型：{most_common_error.replace('_', ' ')}
- 建议：当前方法可能不适用,尝试切换攻击向量或工具
- 提示：考虑是否需要调整 payload、修改请求方法、或尝试其他漏洞类型
""")
        
        # 如果有上次尝试结果，添加反馈
        last_result = state.get("last_attempt_result")
        if last_result:
            prompt_parts.append(f"""
### 📊 上次尝试反馈
```
{last_result}
```

**请分析：**
- 输出中是否有错误信息？
- 是否需要调整攻击载荷？
- 是否需要尝试其他漏洞类型？
""")
        
        # 如果尝试多次失败，建议使用提示
        if attempts >= 5 and not challenge.get("hint_viewed"):
            prompt_parts.append("""
### 💡 建议
尝试次数较多，如需帮助可使用 `view_challenge_hint` 查看提示（会扣分）。
""")
    
    # 进度信息
    solved = state.get("solved_count", 0)
    total = state.get("total_challenges", 0)
    if total > 0:
        prompt_parts.append(f"""
---
**总进度：** {solved}/{total} 题已完成 ({solved*100//total}%)
""")
    
    return SystemMessage(content="\n".join(prompt_parts))

