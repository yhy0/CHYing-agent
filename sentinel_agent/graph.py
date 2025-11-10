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
from typing import Literal
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage
from langchain_core.runnables import RunnableConfig

from sentinel_agent.state import PenetrationTesterState
from sentinel_agent.tools import get_all_tools
from sentinel_agent.common import log_system_event, log_agent_thought
from sentinel_agent.langmem_memory import get_memory_store, get_all_memory_tools


# ==================== LLM 调用重试装饰器 ====================
async def retry_llm_call(llm_func, *args, max_retries=5, base_delay=2.0, **kwargs):
    """
    LLM 调用重试装饰器（指数退避策略）
    
    Args:
        llm_func: LLM 调用函数（如 llm.ainvoke）
        max_retries: 最大重试次数
        base_delay: 基础延迟（秒）
        
    Returns:
        LLM 响应
        
    Raises:
        Exception: 所有重试都失败后抛出最后一个异常
    """
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            result = await llm_func(*args, **kwargs)
            
            # 成功则返回
            if attempt > 0:
                log_system_event(
                    f"[LLM重试] ✅ 第 {attempt + 1} 次尝试成功"
                )
            return result
            
        except Exception as e:
            last_exception = e
            error_msg = str(e)
            
            # 检查是否是速率限制或服务端错误
            is_retryable = any([
                "rate" in error_msg.lower(),
                "limit" in error_msg.lower(),
                "20057" in error_msg,  # MiniMax 特定错误码
                "500" in error_msg,
                "502" in error_msg,
                "503" in error_msg,
                "timeout" in error_msg.lower(),
                "model engine error" in error_msg.lower(),
            ])
            
            if not is_retryable:
                # 非可重试错误，直接抛出
                log_system_event(
                    f"[LLM错误] ❌ 非可重试错误，直接抛出: {error_msg}",
                    level="ERROR"
                )
                raise
            
            if attempt < max_retries - 1:
                # 指数退避：2s, 4s, 8s, 16s, 32s
                delay = base_delay * (2 ** attempt)
                log_system_event(
                    f"[LLM重试] ⚠️ 第 {attempt + 1}/{max_retries} 次失败，{delay:.1f}秒后重试",
                    {"error": error_msg}
                )
                await asyncio.sleep(delay)
            else:
                log_system_event(
                    f"[LLM重试] ❌ 已达最大重试次数 ({max_retries})，放弃调用",
                    {"error": error_msg},
                    level="ERROR"
                )
    
    # 所有重试都失败，抛出最后一个异常
    raise last_exception


# ==================== Advisor Agent 的系统提示词 ====================
ADVISOR_SYSTEM_PROMPT = """
# CTF 安全顾问（Advisor Agent）

你是一个经验丰富的 CTF 安全顾问，专门为主攻击手提供建议和思路。

## 你的角色

- **身份**：顾问（不直接执行攻击）
- **任务**：分析题目，总结进度，提供攻击建议和思路
- **输出**：结构化的分析报告（不调用工具）

## 输出格式（必须严格遵守）

每次分析请按以下格式输出：

### 📊 进度总结

**已尝试的攻击路径**：
- 路径 1：[工具] [方法] → [结果：成功/失败] → [关键发现]
- 路径 2：[工具] [方法] → [结果：成功/失败] → [关键发现]
- ...

**当前漏洞假设**：
- 假设 1：[漏洞类型]（置信度 XX%）- 依据：[证据]
- 假设 2：[漏洞类型]（置信度 XX%）- 依据：[证据]

**已排除的方向**：
- ❌ [方法]：已尝试 X 次，均失败，原因：[分析]

**关键信息汇总**：
- 目标信息：[IP/端口/服务/版本]
- 已发现的端点/路径：[列表]
- 已发现的参数/字段：[列表]
- 错误信息/提示：[关键线索]

### 💡 下一步建议

**优先方案**（置信度 XX%）：
- **攻击方向**：[具体方法]
- **推荐工具**：execute_python_poc / execute_command
- **理由**：[为什么这个方向最有希望]
- **具体步骤**：
  1. [步骤 1]
  2. [步骤 2]
- **期望结果**：[如何判断成功]

**备选方案**（置信度 XX%）：
- **攻击方向**：[具体方法]
- **推荐工具**：execute_python_poc / execute_command
- **理由**：[为什么值得尝试]

### ⚠️ 风险提示

- **注意事项**：[潜在风险/容易犯的错误]
- **工具选择建议**：
  - 如果主攻击手使用了 curl 且失败，强烈建议切换到 Python + requests
  - 如果需要多步骤操作，优先使用 execute_python_poc
- **提示建议**：[是否建议使用 view_challenge_hint]

## 工具选择建议

### 🐍 Python 沙箱（execute_python_poc）
**推荐场景：**
- HTTP 请求、API 测试
- 登录、Cookie、JWT、Session 管理
- 暴力破解、爆破攻击
- SQL 注入、XSS、命令注入测试
- 需要循环、条件判断、数据处理

### 🐳 Kali Docker（execute_command）
**推荐场景：**
- 渗透测试工具（nmap, sqlmap, nikto, dirb）
- 系统命令（ls, cat, grep）
- 简单的单次命令

## 重要规则

1. **只提供建议，不调用工具**
2. **结构化输出**：严格按照上述格式
3. **给出置信度**：帮助主攻击手判断优先级
4. **明确推荐工具**：execute_python_poc vs execute_command
5. **多视角思考**：提供主攻击手可能忽略的角度
6. **避免重复**：如果主攻击手已经尝试过，建议新方向
7. **总结进度**：每次都要回顾已尝试的路径，避免重复劳动

现在开始你的分析！
"""


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
    # ==================== 1. 初始化记忆系统 ====================
    memory_store = get_memory_store()
    memory_tools = get_all_memory_tools()
    
    log_system_event(
        "--- 初始化多 Agent 协作系统 ---", 
        {
            "main_llm": type(main_llm).__name__,
            "advisor_llm": type(advisor_llm).__name__,
            "memory_tools_count": len(memory_tools),
        }
    )
    
    # ==================== 2. 获取所有工具 ====================
    pentest_tools = get_all_tools()
    all_tools = pentest_tools + memory_tools
    
    # 只有主 Agent 绑定工具
    main_llm_with_tools = main_llm.bind_tools(all_tools)
    # 顾问 Agent 不绑定工具（只提供建议）
    
    # ==================== 3. 创建自定义 ToolNode（带状态更新）====================
    base_tool_node = ToolNode(all_tools)
    
    async def tool_node(state: PenetrationTesterState):
        """
        自定义工具节点：执行工具后检查是否需要更新状态
        
        关键功能：
        1. 执行工具调用
        2. 检查 submit_flag 结果，自动设置 flag 和 is_finished
        3. ⭐ 追踪失败次数（用于智能路由）
        4. 让并发任务在解决题目后立即退出
        """
        # 执行基础工具调用
        result = await base_tool_node.ainvoke(state)
        
        # ⭐ 获取本次执行的工具类型（用于智能路由）
        current_action_type = None
        messages = state.get("messages", [])
        if messages:
            last_message = messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                # 记录第一个工具调用的名称
                current_action_type = last_message.tool_calls[0].get("name")
        
        # ⭐ 分析本次执行是否失败（用于智能路由）
        is_failure = False
        failure_keywords = ["error", "failed", "exception", "无法", "错误", "失败", "not found", "denied"]
        
        # 检查工具执行结果
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    content = msg.content.lower()
                    
                    # 1. 检测答案正确的标记（成功）
                    if "✓ 答案正确" in content or "答案正确！获得" in content:
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
                                            break
                    
                    # 2. 检测失败标记
                    elif any(keyword in content for keyword in failure_keywords):
                        is_failure = True
        
        # ⭐ 更新失败计数和操作类型（用于智能路由）
        last_action_type = state.get("last_action_type")
        consecutive_failures = state.get("consecutive_failures", 0)
        
        if is_failure:
            # 如果与上次是同类型操作，增加失败计数
            if current_action_type == last_action_type:
                consecutive_failures += 1
            else:
                # 切换了操作类型，重置计数
                consecutive_failures = 1
            
            log_system_event(
                f"[智能路由] 检测到失败，连续失败次数: {consecutive_failures}",
                {"action_type": current_action_type}
            )
        else:
            # 成功或无明显错误，重置计数
            consecutive_failures = 0
        
        result["consecutive_failures"] = consecutive_failures
        result["last_action_type"] = current_action_type
        
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
        # 检测是否刚获取完建议（避免重复咨询）
        if state.get("advisor_suggestion") and not state.get("last_action_output"):
            log_agent_thought("[Advisor] 建议尚未被使用，跳过重复咨询")
            return {"messages": []}  # 返回空更新
        
        # 构建顾问的上下文
        advisor_messages = [SystemMessage(content=ADVISOR_SYSTEM_PROMPT)]
        
        # 构建动态提示词
        context_parts = []
        
        # 0. 比赛状态总览（新增）
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
            
            context_parts.append(f"""
## 📊 比赛状态总览

- **当前阶段**: {current_phase.upper()}
- **当前积分**: {current_score} 分
- **已解题数**: {solved_count}/{total_challenges} ({solved_count*100//total_challenges if total_challenges > 0 else 0}%)
- **耗时**: {elapsed_time if elapsed_time else "未知"}
- **已使用提示**: {state.get('hint_used_count', 0)} 次
""")
        
        # 1. 赛题列表信息
        if state.get("challenges"):
            challenges = state["challenges"]
            context_parts.append(f"""
## 📋 可用赛题列表

共有 {len(challenges)} 道题目：
{_format_challenges_list(challenges)}
""")
        
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
            target_info = challenge.get("target_info", {})
            ip = target_info.get("ip", "unknown")
            ports = target_info.get("port", [])
            
            context_parts.append(f"""
## 🎯 当前攻击目标

- **题目代码**: {code}
- **难度**: {difficulty.upper()}
- **满分**: {points} 分
- **目标**: {ip}:{','.join(map(str, ports))}
- **已尝试次数**: {attempts}
- **提示状态**: {"已查看 💡（得分会扣除惩罚分）" if hint_viewed else "未查看"}
""")
        
        # 3. 历史操作
        action_history = state.get('action_history', [])
        if action_history:
            context_parts.append(f"""
## 📜 主攻击手的历史操作

{_format_action_history(action_history)}
""")
        
        # 4. 最近一次执行结果（智能摘要）
        last_output = state.get('last_action_output', '')
        if last_output:
            # 智能截断：保留关键错误信息（提高到 5000 以保留更多上下文）
            preview = _smart_truncate_output(last_output, max_len=5000)
            context_parts.append(f"""
## 🔍 最近一次执行结果

```
{preview}
```
""")
        
        # 5. 已发现的信息
        vulnerabilities = state.get('potential_vulnerabilities', [])
        if vulnerabilities:
            context_parts.append(f"""
## 🔐 已发现的潜在漏洞

{chr(10).join(f"- {v}" for v in vulnerabilities)}
""")
        
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
        
        # ⭐ 调用顾问 LLM（带重试）
        try:
            advisor_response: AIMessage = await retry_llm_call(
                advisor_llm.ainvoke,
                advisor_messages,
                max_retries=5,
                base_delay=2.0
            )
        except Exception as e:
            # LLM 调用失败后的降级处理
            log_system_event(
                "[Advisor] ❌ LLM 调用失败，跳过本次建议",
                {"error": str(e)},
                level="ERROR"
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
        from sentinel_agent.prompts import SYSTEM_PROMPT
        
        # 构建主 Agent 的系统提示词
        system_prompt_parts = [SYSTEM_PROMPT]
        
        # 如果有顾问建议，添加到系统提示词
        advisor_suggestion = state.get("advisor_suggestion")
        if advisor_suggestion:
            system_prompt_parts.append(f"""
---

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
        messages = list(state.get("messages", []))
        
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
        
        # ⭐ 调用主 LLM（带重试）
        try:
            ai_message: AIMessage = await retry_llm_call(
                main_llm_with_tools.ainvoke,
                messages,
                max_retries=5,
                base_delay=2.0
            )
        except Exception as e:
            # LLM 调用失败后的降级处理
            log_system_event(
                "[Main Agent] ❌ LLM 调用失败，使用降级策略",
                {"error": str(e)},
                level="ERROR"
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
        
        # 4. 工具执行完 → 获取顾问新建议
        # 判断依据：上一次是工具执行（通过检查 last_action_output）
        if state.get("last_action_output"):
            log_system_event("[Router] 工具执行完毕 → 咨询顾问")
            return "advisor"
        
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
        
        # ⭐ 3. 智能决策：是否需要 Advisor 介入
        consecutive_failures = state.get("consecutive_failures", 0)
        request_help = state.get("request_advisor_help", False)
        
        # 3.1 连续失败次数过多 → 需要 Advisor 帮助
        if consecutive_failures >= 3:
            log_system_event(
                f"[智能路由] 🆘 连续失败 {consecutive_failures} 次，请求 Advisor 帮助",
                {"action_type": state.get("last_action_type")}
            )
            return "advisor"
        
        # 3.2 Main Agent 主动请求帮助
        if request_help:
            log_system_event("[智能路由] 🆘 Main Agent 主动请求 Advisor 帮助")
            return "advisor"
        
        # 3.3 关键节点检查（每隔 5 次尝试咨询一次 Advisor）
        if attempts > 0 and attempts % 5 == 0:
            log_system_event(
                f"[智能路由] 🔄 达到关键节点（第 {attempts} 次尝试），咨询 Advisor"
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

def _smart_truncate_output(output: str, max_len: int = 5000) -> str:
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


def _format_challenges_list(challenges: list) -> str:
    """格式化赛题列表（显示完整信息）"""
    if not challenges:
        return "暂无赛题"
    
    formatted = []
    for i, ch in enumerate(challenges, 1):
        # 提取关键信息
        code = ch.get('challenge_code', ch.get('code', 'unknown'))
        difficulty = ch.get('difficulty', 'unknown')
        points = ch.get('points', 0)
        hint_viewed = ch.get('hint_viewed', False)
        solved = ch.get('solved', False)
        target_info = ch.get('target_info', {})
        ip = target_info.get('ip', 'unknown')
        ports = target_info.get('port', [])
        
        # 格式化
        status = "✅ 已解决" if solved else "🔓 未解决"
        hint_mark = "💡" if hint_viewed else ""
        
        formatted.append(
            f"{i}. **{code}** ({difficulty}, {points}分) - {status} {hint_mark}\n"
            f"   目标: {ip}:{','.join(map(str, ports))}"
        )
    
    return "\n".join(formatted)


def _format_action_history(action_history: list) -> str:
    """格式化操作历史"""
    if not action_history:
        return "暂无操作历史"
    
    # 只显示最近 5 次
    recent = action_history[-5:]
    formatted = []
    for i, action in enumerate(recent, 1):
        formatted.append(f"{i}. {action}")
    
    return "\n".join(formatted)


def _build_main_system_prompt(state: PenetrationTesterState, base_parts: list) -> SystemMessage:
    """构建主 Agent 的动态系统提示词"""
    original_prompt = _build_system_prompt(state)
    
    # 合并基础部分和动态部分
    combined = "\n\n".join(base_parts) + "\n\n" + original_prompt.content
    
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
    
    # 阶段 1: 尚未获取赛题列表
    if not state.get("challenges"):
        prompt_parts.append("""
## 🎯 当前任务：获取赛题列表

这是一个 CTF 比赛环境。你需要：
1. **调用 `get_challenge_list` 工具** 获取所有可用赛题
2. 查看赛题信息（URL、类型、难度）
3. 准备开始攻击

**注意：** 不要使用 nmap 扫描，这是 Web 应用比赛。
""")
        return SystemMessage(content="\n".join(prompt_parts))
    
    # 阶段 2: 已有赛题列表，选择赛题
    challenges = state.get("challenges", [])
    completed = state.get("completed_challenges", [])
    remaining = [c for c in challenges if c.get("challenge_code", c.get("code")) not in completed]
    
    # 添加比赛状态总览
    current_score = state.get("current_score", 0)
    solved_count = state.get("solved_count", 0)
    total_challenges = state.get("total_challenges", 0)
    current_phase = state.get("current_phase", "unknown")
    start_time = state.get("start_time")
    
    if total_challenges > 0:
        elapsed_time = ""
        if start_time:
            import time
            elapsed_seconds = int(time.time() - start_time)
            elapsed_time = f"{elapsed_seconds // 60}分{elapsed_seconds % 60}秒"
        
        prompt_parts.append(f"""
## 📊 比赛状态总览

- **阶段**: {current_phase.upper()}
- **当前积分**: {current_score} 分
- **进度**: {solved_count}/{total_challenges} ({solved_count*100//total_challenges if total_challenges > 0 else 0}%)
- **耗时**: {elapsed_time if elapsed_time else "未知"}
- **剩余题目**: {len(remaining)} 道
""")
    
    if remaining and not state.get("current_challenge"):
        next_challenge = remaining[0]
        code = next_challenge.get("challenge_code", next_challenge.get("code"))
        difficulty = next_challenge.get("difficulty", "unknown")
        points = next_challenge.get("points", 0)
        target_info = next_challenge.get("target_info", {})
        ip = target_info.get("ip", "unknown")
        ports = target_info.get("port", [])
        
        prompt_parts.append(f"""
## 📋 建议攻击下一题

**题目代码**: {code}
- **难度**: {difficulty.upper()}
- **满分**: {points} 分
- **目标**: {ip}:{','.join(map(str, ports))}

请开始攻击此赛题。
""")
        return SystemMessage(content="\n".join(prompt_parts))
    
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
        target_info = challenge.get("target_info", {})
        ip = target_info.get("ip", "unknown")
        ports = target_info.get("port", [])
        
        # 构建目标 URL（假设是 HTTP）
        port_str = str(ports[0]) if ports else "80"
        target_url = f"http://{ip}:{port_str}"
        
        prompt_parts.append(f"""
## 🎯 当前攻击中：{code}

### 赛题信息
- **代码**：`{code}`
- **难度**：{difficulty.upper()}
- **满分**：{points} 分
- **目标**：{target_url}
- **尝试次数**：{attempts}
- **提示状态**：{"已查看 💡（扣分）" if hint_viewed else "未查看"}

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
        
        # 检测失败模式并提供警告
        action_history = state.get("action_history", [])
        if len(action_history) >= 3:
            recent_actions = action_history[-5:]  # 检查最近 5 次操作
            recent_text = " ".join(str(a) for a in recent_actions)
            
            # 检测 curl 引号/转义错误
            if recent_text.count("curl") >= 2 and ("Exit Code: 2" in recent_text or "unexpected EOF" in recent_text):
                prompt_parts.append("""
### ⚠️ 检测到失败模式：curl 引号/转义问题
**警告**：你已经多次遇到 curl 命令的引号转义错误（Exit Code: 2 或 unexpected EOF）。

**立即切换策略**：
- ❌ **停止尝试修复 curl 引号** - 这会浪费宝贵的尝试次数
- ✅ **立即使用 `execute_python_poc`** - Python requests 库会自动处理所有引号、Cookie、会话问题

**示例代码**：
```python
import requests
session = requests.Session()
# 登录
resp = session.post("http://target/login", data={"username": "demo", "password": "demo"})
# session 会自动保持 Cookie
data = session.get("http://target/protected").text
print(data)
```
""")
            
            # 检测重复相同命令
            if len(set(recent_actions[-3:])) == 1:
                prompt_parts.append("""
### ⚠️ 检测到失败模式：重复相同命令
**警告**：你正在重复执行相同的命令，这不会产生新的结果。

**建议行动**：
1. 分析为什么上次失败
2. 尝试完全不同的方法
3. 考虑换一个攻击角度
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

