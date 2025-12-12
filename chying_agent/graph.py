"""
多 Agent 协作图 V2（三层架构）
=====================================

三层架构：
- 规划层：Advisor Agent (MiniMax) + Main Agent (DeepSeek) - 只负责规划与决策
- 执行层：PoC Agent + Docker Agent - 专注执行
- 知识层：Skills (SKILL.md) - 按需加载漏洞知识库

架构图：
┌──────────────────────────────────────────────────────────────┐
│                        规划层                                 │
│  ┌──────────────┐         ┌──────────────┐                   │
│  │ Advisor      │ ──────> │ Main Agent   │                   │
│  │ (MiniMax)    │ 提供建议 │ (DeepSeek)   │                   │
│  │ +Skills加载  │         │ 规划与决策    │                   │
│  └──────────────┘         └──────┬───────┘                   │
└──────────────────────────────────┼───────────────────────────┘
                                   │ 分发任务
                                   ▼
┌──────────────────────────────────────────────────────────────┐
│                        执行层                                 │
│  ┌──────────────┐         ┌──────────────┐                   │
│  │ PoC Agent    │         │ Docker Agent │                   │
│  │ Python脚本   │         │ Kali工具     │                   │
│  └──────────────┘         └──────────────┘                   │
└──────────────────────────────────────────────────────────────┘

作者：CHYing
日期：2025-12-10
"""
import asyncio
import time
import os
import logging
from typing import Literal, Optional
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage, ToolMessage
from langchain_core.runnables import RunnableConfig

from chying_agent.state import PenetrationTesterState
from chying_agent.tools import get_all_tools
from chying_agent.common import log_system_event, log_agent_thought
from chying_agent.langmem_memory import get_memory_store, get_all_memory_tools
from chying_agent.utils.rate_limiter import get_rate_limiter
from chying_agent.utils.util import retry_llm_call
from chying_agent.utils.failure_detector import detect_failure_with_llm

# 导入模块化的 Agent
from chying_agent.agents.advisor import ADVISOR_SYSTEM_PROMPT
from chying_agent.agents.main_agent import MAIN_AGENT_SYSTEM_PROMPT
from chying_agent.agents.poc_agent import POC_AGENT_SYSTEM_PROMPT
from chying_agent.agents.docker_agent import DOCKER_AGENT_SYSTEM_PROMPT
from chying_agent.prompts_book import (
    TOOL_OUTPUT_SUMMARY_PROMPT,
    MAIN_AGENT_PLANNER_PROMPT,
    build_advisor_context,
    build_main_context,
    get_target_url,
    get_target_info,
)

# 导入 Skills 加载器
from chying_agent.skills.skill_loader import load_skills_for_context, get_skill_summary


# ==================== 初始化全局速率限制器 ====================
DEEPSEEK_RPS = float(os.getenv("DEEPSEEK_REQUESTS_PER_SECOND", "2.0"))
MINIMAX_RPS = float(os.getenv("MINIMAX_REQUESTS_PER_SECOND", "2.0"))

deepseek_limiter = get_rate_limiter("deepseek_llm", requests_per_second=DEEPSEEK_RPS, burst_size=5)
minimax_limiter = get_rate_limiter("minimax_llm", requests_per_second=MINIMAX_RPS, burst_size=5)


async def build_multi_agent_graph(config: RunnableConfig):
    """
    构建多 Agent 协作图（三层架构）

    Args:
        config: LangGraph 运行时配置

    Returns:
        编译后的 LangGraph 应用
    """
    # ==================== 0. 初始化 LLM ====================
    from chying_agent.model import create_model
    from chying_agent.core.singleton import get_config_manager
    from langchain_openai import ChatOpenAI

    agent_config = get_config_manager().config

    # 主 LLM (DeepSeek) - 用于 Main Agent 和执行层
    main_llm = create_model(agent_config)
    log_system_event("[Graph V2] 初始化 main_llm (DeepSeek)")

    # 顾问 LLM (MiniMax)
    advisor_llm = ChatOpenAI(
        base_url=os.getenv("SILICONFLOW_BASE_URL", "https://api.siliconflow.cn/v1"),
        api_key=os.getenv("SILICONFLOW_API_KEY"),
        model=os.getenv("SILICONFLOW_MODEL", "MiniMaxAI/MiniMax-M2"),
        temperature=0.7,
        max_tokens=8192,
        timeout=600,
        max_retries=10
    )
    log_system_event("[Graph V2] 初始化 advisor_llm (MiniMax)")

    # 从 config 中提取 manual_mode
    manual_mode = False
    if config and hasattr(config, "get"):
        configurable = config.get("configurable", {})
        manual_mode = configurable.get("manual_mode", False)

    return await _build_graph_internal(main_llm, advisor_llm, manual_mode=manual_mode)


async def _build_graph_internal(
    main_llm: BaseChatModel,
    advisor_llm: BaseChatModel,
    manual_mode: bool = False,
    graph_name: str = "LangGraph"
):
    """
    构建三层架构图的内部实现

    Args:
        main_llm: 主 LLM
        advisor_llm: 顾问 LLM
        manual_mode: 是否手动模式
        graph_name: 图名称（用于 Langfuse trace name）
    """
    # ==================== 1. 初始化记忆和工具 ====================
    memory_store = get_memory_store()
    memory_tools = get_all_memory_tools(manual_mode=manual_mode)
    pentest_tools = get_all_tools()
    all_tools = pentest_tools + memory_tools

    # 分离工具：PoC Agent 用 execute_python_poc，Docker Agent 用 execute_command
    poc_tool = next((t for t in pentest_tools if t.name == "execute_python_poc"), None)
    docker_tool = next((t for t in pentest_tools if t.name == "execute_command"), None)
    submit_tool = next((t for t in memory_tools if t.name == "submit_flag"), None)

    log_system_event(
        f"[Graph V2] 初始化三层架构",
        {
            "poc_tool": poc_tool.name if poc_tool else None,
            "docker_tool": docker_tool.name if docker_tool else None,
            "submit_tool": submit_tool.name if submit_tool else None,
            "manual_mode": manual_mode
        }
    )

    # 执行层 Agent 绑定各自的工具
    poc_llm_with_tools = main_llm.bind_tools([poc_tool]) if poc_tool else None
    docker_llm_with_tools = main_llm.bind_tools([docker_tool]) if docker_tool else None

    # 创建 ToolNode 用于执行工具
    base_tool_node = ToolNode(all_tools)

    # ==================== 2. Advisor Agent 节点 ====================
    async def advisor_node(state: PenetrationTesterState):
        """
        顾问 Agent - 提供攻击建议 + 按需加载 Skills
        """
        # 构建系统提示词
        advisor_sys_prompt = ADVISOR_SYSTEM_PROMPT

        # ⭐ 按需加载 Skills
        hint_content = ""
        target_info_msg = ""
        if state.get("current_challenge"):
            challenge = state["current_challenge"]
            hint_content = challenge.get("hint_content", "")
            target_info = challenge.get("target_info", {})
            ip = target_info.get("ip", "unknown")
            ports = target_info.get("port", [])
            target_info_msg = f"- **目标**: {ip}:{','.join(map(str, ports))}"

        # 加载相关 Skills
        skills_content = load_skills_for_context(
            hint=hint_content,
            max_skills=2
        )

        if skills_content:
            advisor_sys_prompt += f"\n\n---\n\n# 漏洞知识库（按需加载）\n\n{skills_content}"
            log_system_event("[Advisor] 已加载漏洞知识库")

        if hint_content:
            advisor_sys_prompt += f"\n## 目标##\n{target_info_msg}\n## 题目提示(**非常重要**): \n\n{hint_content}\n\n"

        advisor_messages = [SystemMessage(content=advisor_sys_prompt)]

        # 构建动态上下文
        context_parts = build_advisor_context(state)

        if context_parts:
            full_context = "\n".join(context_parts) + "\n\n---\n\n请基于以上信息，提供你的攻击建议。"
            advisor_messages.append(HumanMessage(content=full_context))
        else:
            advisor_messages.append(HumanMessage(content="主攻击手尚未选择题目或开始攻击。请等待进一步信息。"))

        log_agent_thought("[Advisor] 开始分析...")

        try:
            advisor_response: AIMessage = await retry_llm_call(
                advisor_llm.ainvoke,
                advisor_messages,
                max_retries=5,
                base_delay=2.0,
                limiter=minimax_limiter
            )
        except Exception as e:
            log_system_event(
                "[Advisor] ❌ LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "advisor_suggestion": "",
                "messages": []
            }

        log_agent_thought(
            "[MiniMax] 提供建议",
            {"advice": advisor_response.content[:200] + "..."}
        )

        return {
            "advisor_suggestion": advisor_response.content,
            "messages": []
        }

    # ==================== 3. Main Agent 节点（规划模式）====================
    async def main_agent_node(state: PenetrationTesterState):
        """
        主 Agent - 规划与决策（不直接执行工具）

        输出格式：
        - [DISPATCH_TASK] ... [/DISPATCH_TASK]：分发任务给执行层
        - [REQUEST_ADVISOR_HELP]：请求顾问帮助
        - [SUBMIT_FLAG:flag{{...}}]：提交 FLAG（花括号内填写实际FLAG内容）
        """
        # 构建当前上下文
        current_context = build_main_context(state)

        # 构建系统提示词
        system_prompt = MAIN_AGENT_PLANNER_PROMPT.format(current_context=current_context)

        # 添加顾问建议
        advisor_suggestion = state.get("advisor_suggestion")
        if advisor_suggestion:
            system_prompt += f"""

---

## 🤝 顾问建议

{advisor_suggestion}

**请参考顾问建议，制定你的攻击计划。**
"""

        messages = [SystemMessage(content=system_prompt)]

        # 添加历史消息（限制数量）
        history = list(state.get("messages", []))
        max_history = int(os.getenv("MAX_HISTORY_MESSAGES", "10"))
        if len(history) > max_history:
            history = history[-max_history:]

        messages.extend(history)

        log_agent_thought("[Main Agent] 开始规划...")

        try:
            ai_message: AIMessage = await retry_llm_call(
                main_llm.ainvoke,  # 不绑定工具，纯规划模式
                messages,
                max_retries=5,
                base_delay=2.0,
                limiter=deepseek_limiter
            )
        except Exception as e:
            log_system_event(
                "[Main Agent] ❌ LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "messages": [AIMessage(content=f"规划失败：{str(e)} [REQUEST_ADVISOR_HELP]")],
                "advisor_suggestion": "",
                "request_advisor_help": True
            }

        content = ai_message.content or ""

        # 解析输出
        request_help = "[REQUEST_ADVISOR_HELP]" in content
        dispatch_task = _parse_dispatch_task(content)
        submit_flag = _parse_submit_flag(content)

        log_agent_thought(
            "[Main Agent] 规划结果",
            {
                "has_dispatch": dispatch_task is not None,
                "has_submit": submit_flag is not None,
                "request_help": request_help
            }
        )

        # 存储分发任务到状态
        result = {
            "messages": [ai_message],
            "advisor_suggestion": "",
            "request_advisor_help": request_help
        }

        if dispatch_task:
            result["pending_task"] = dispatch_task

        if submit_flag:
            result["pending_flag"] = submit_flag

        return result

    # ==================== 4. PoC Agent 节点 ====================
    async def poc_agent_node(state: PenetrationTesterState):
        """
        PoC Agent - 执行 Python 脚本

        处理两种情况：
        1. pending_flag: Main Agent 解析出的 FLAG，需要直接提交
        2. pending_task: 需要执行的 Python PoC 任务
        """
        # 优先处理 pending_flag（Main Agent 解析出的 FLAG）
        pending_flag = state.get("pending_flag")
        if pending_flag:
            if submit_tool:
                log_system_event(f"[PoC Agent] 提交 FLAG: {pending_flag[:20]}...")
                challenge = state.get("current_challenge", {})
                challenge_code = challenge.get("challenge_code", challenge.get("code", "unknown"))

                # 构造工具调用消息
                tool_call_id = f"submit_flag_{challenge_code}"
                ai_message = AIMessage(
                    content="",
                    tool_calls=[{
                        "id": tool_call_id,
                        "name": "submit_flag",
                        "args": {
                            "challenge_code": challenge_code,
                            "flag": pending_flag
                        }
                    }]
                )
                return {
                    "messages": [ai_message],
                    "pending_flag": None,  # 清除已处理的 FLAG
                    "pending_task": None
                }
            else:
                # 手动模式：没有 submit_tool，直接输出 FLAG 并标记完成
                log_system_event(f"[PoC Agent] 手动模式 - 发现 FLAG: {pending_flag}")
                ai_message = AIMessage(
                    content=f"🎉 发现 FLAG: {pending_flag}\n\n（手动模式，请自行提交）"
                )
                return {
                    "messages": [ai_message],
                    "pending_flag": None,
                    "pending_task": None,
                    "flag": pending_flag,
                    "is_finished": True
                }

        pending_task = state.get("pending_task") or {}
        task_description = pending_task.get("task", "")

        if not task_description:
            log_system_event("[PoC Agent] 没有待执行的任务")
            return {"messages": [], "pending_task": None}

        # 构建提示词
        target_url = get_target_url(state)
        hint_content = ""
        if state.get("current_challenge"):
            hint_content = state["current_challenge"].get("hint_content", "")

        prompt = f"""
{POC_AGENT_SYSTEM_PROMPT}

---

## 当前任务

{task_description}

## 目标信息

- **URL**: {target_url}
{"- **提示**: " + hint_content if hint_content else ""}

请编写并执行 Python PoC 代码来完成任务。
"""

        messages = [
            SystemMessage(content=prompt),
            HumanMessage(content="请执行任务。")
        ]

        log_agent_thought(f"[PoC Agent] 执行任务: {task_description[:100]}...")

        try:
            ai_message: AIMessage = await retry_llm_call(
                poc_llm_with_tools.ainvoke,
                messages,
                max_retries=3,
                base_delay=1.0,
                limiter=deepseek_limiter
            )
        except Exception as e:
            log_system_event(
                "[PoC Agent] ❌ LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "messages": [AIMessage(content=f"PoC 执行失败：{str(e)}")],
                "pending_task": None
            }

        return {
            "messages": [ai_message],
            "pending_task": None  # 清除已处理的任务
        }

    # ==================== 5. Docker Agent 节点 ====================
    async def docker_agent_node(state: PenetrationTesterState):
        """
        Docker Agent - 执行 Kali 工具
        """
        pending_task = state.get("pending_task") or {}
        task_description = pending_task.get("task", "")

        if not task_description:
            log_system_event("[Docker Agent] 没有待执行的任务")
            return {"messages": [], "pending_task": None}

        # 构建提示词
        target_info = get_target_info(state)
        hint_content = ""
        if state.get("current_challenge"):
            hint_content = state["current_challenge"].get("hint_content", "")

        prompt = f"""
{DOCKER_AGENT_SYSTEM_PROMPT}

---

## 当前任务

{task_description}

## 目标信息

{target_info}
{"- **提示**: " + hint_content if hint_content else ""}

请执行适当的 Kali 工具命令来完成任务。
"""

        messages = [
            SystemMessage(content=prompt),
            HumanMessage(content="请执行任务。")
        ]

        log_agent_thought(f"[Docker Agent] 执行任务: {task_description[:100]}...")

        try:
            ai_message: AIMessage = await retry_llm_call(
                docker_llm_with_tools.ainvoke,
                messages,
                max_retries=3,
                base_delay=1.0,
                limiter=deepseek_limiter
            )
        except Exception as e:
            log_system_event(
                "[Docker Agent] ❌ LLM 调用失败",
                {"error": str(e)},
                level=logging.ERROR
            )
            return {
                "messages": [AIMessage(content=f"Docker 执行失败：{str(e)}")],
                "pending_task": None
            }

        return {
            "messages": [ai_message],
            "pending_task": None
        }

    # ==================== 6. Tool 执行节点 ====================
    async def tool_node(state: PenetrationTesterState):
        """
        工具执行节点 - 执行 PoC Agent 或 Docker Agent 的工具调用
        """
        # 执行工具
        result = await base_tool_node.ainvoke(state)

        # 检查是否找到 FLAG
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    if "答案正确" in msg.content:
                        # 提取 FLAG
                        messages = state.get("messages", [])
                        if messages:
                            last_message = messages[-1]
                            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                                for tool_call in last_message.tool_calls:
                                    if tool_call.get("name") == "submit_flag":
                                        submitted_flag = tool_call.get("args", {}).get("flag")
                                        if submitted_flag:
                                            result["flag"] = submitted_flag
                                            result["is_finished"] = True
                                            result["consecutive_failures"] = 0
                                            return result

        # 检测失败
        is_failure = False
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    content = msg.content.lower()
                    failure_keywords = ["error", "failed", "exception", "无法", "错误", "失败"]
                    is_failure = any(kw in content for kw in failure_keywords)

        consecutive_failures = state.get("consecutive_failures", 0)
        if is_failure:
            consecutive_failures += 1
        else:
            consecutive_failures = 0

        result["consecutive_failures"] = consecutive_failures

        return result

    # ==================== 7. 路由函数 ====================
    def route_after_main(state: PenetrationTesterState) -> Literal["poc_agent", "docker_agent", "advisor", "end"]:
        """
        Main Agent 之后的路由
        """
        # 检查是否完成
        if state.get("flag") or state.get("is_finished"):
            return "end"

        # 检查是否请求帮助
        if state.get("request_advisor_help"):
            return "advisor"

        # 检查是否有待分发的任务
        pending_task = state.get("pending_task")
        if pending_task:
            agent = pending_task.get("agent", "poc")
            if agent == "docker":
                log_system_event("[Router] 分发任务到 Docker Agent")
                return "docker_agent"
            else:
                log_system_event("[Router] 分发任务到 PoC Agent")
                return "poc_agent"

        # 检查是否有待提交的 FLAG
        pending_flag = state.get("pending_flag")
        if pending_flag:
            # 直接提交 FLAG（通过 PoC Agent）
            return "poc_agent"

        # 默认返回 advisor
        return "advisor"

    def route_after_execution(state: PenetrationTesterState) -> Literal["tools", "main_agent", "end"]:
        """
        执行层 Agent 之后的路由
        """
        # 检查是否完成
        if state.get("flag") or state.get("is_finished"):
            return "end"

        # 检查是否有工具调用
        messages = state.get("messages", [])
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                return "tools"

        # 返回 Main Agent 继续规划
        return "main_agent"

    def route_after_tools(state: PenetrationTesterState) -> Literal["main_agent", "advisor", "end"]:
        """
        工具执行后的路由
        """
        # 检查是否完成
        if state.get("flag") or state.get("is_finished"):
            return "end"

        # 检查是否超限
        messages = state.get("messages", [])
        attempts = len([m for m in messages if hasattr(m, 'tool_calls') and m.tool_calls])

        from chying_agent.core.constants import AgentConfig
        max_attempts = AgentConfig.get_max_attempts()

        if attempts > max_attempts:
            return "end"

        # 检查是否需要 Advisor
        consecutive_failures = state.get("consecutive_failures", 0)
        from chying_agent.core.constants import SmartRoutingConfig
        failures_threshold = SmartRoutingConfig.get_failures_threshold()

        if consecutive_failures > 0 and consecutive_failures % failures_threshold == 0:
            return "advisor"

        # 返回 Main Agent
        return "main_agent"

    # ==================== 8. 构建 StateGraph ====================
    workflow = StateGraph(PenetrationTesterState)

    # 添加节点
    workflow.add_node("advisor", advisor_node)
    workflow.add_node("main_agent", main_agent_node)
    workflow.add_node("poc_agent", poc_agent_node)
    workflow.add_node("docker_agent", docker_agent_node)
    workflow.add_node("tools", tool_node)

    # 设置入口
    workflow.set_entry_point("advisor")

    # 定义边
    workflow.add_edge("advisor", "main_agent")

    workflow.add_conditional_edges(
        "main_agent",
        route_after_main,
        {
            "poc_agent": "poc_agent",
            "docker_agent": "docker_agent",
            "advisor": "advisor",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "poc_agent",
        route_after_execution,
        {
            "tools": "tools",
            "main_agent": "main_agent",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "docker_agent",
        route_after_execution,
        {
            "tools": "tools",
            "main_agent": "main_agent",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "tools",
        route_after_tools,
        {
            "main_agent": "main_agent",
            "advisor": "advisor",
            "end": END
        }
    )

    # 编译图（传入 name 参数，用于 Langfuse trace name）
    app = workflow.compile(store=memory_store, name=graph_name)

    log_system_event("[Graph V2] 三层架构图构建完成")
    return app


# ==================== 辅助函数 ====================


def _parse_dispatch_task(content: str) -> Optional[dict]:
    """解析任务分发指令"""
    import re

    pattern = r'\[DISPATCH_TASK\]\s*agent:\s*(\w+)\s*task:\s*\|?\s*(.*?)\[/DISPATCH_TASK\]'
    match = re.search(pattern, content, re.DOTALL)

    if match:
        return {
            "agent": match.group(1).strip().lower(),
            "task": match.group(2).strip()
        }

    return None


def _parse_submit_flag(content: str) -> Optional[str]:
    """解析 FLAG 提交指令"""
    import re

    pattern = r'\[SUBMIT_FLAG:(.*?)\]'
    match = re.search(pattern, content)

    if match:
        return match.group(1).strip()

    return None


# ==================== 兼容性包装 ====================

async def build_multi_agent_graph_with_llms(
    main_llm: BaseChatModel,
    advisor_llm: BaseChatModel,
    manual_mode: bool = False,
    graph_name: str = "LangGraph"
):
    """
    构建三层架构图（支持传入自定义 LLM）

    Args:
        main_llm: 主 LLM
        advisor_llm: 顾问 LLM
        manual_mode: 是否手动模式
        graph_name: 图名称（用于 Langfuse trace name）
    """
    return await _build_graph_internal(main_llm, advisor_llm, manual_mode=manual_mode, graph_name=graph_name)
