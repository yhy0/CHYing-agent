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


# ==================== Advisor Agent 的系统提示词 ====================
ADVISOR_SYSTEM_PROMPT = """
# CTF 安全顾问（Advisor Agent）

你是一个经验丰富的 CTF 安全顾问，专门为主攻击手提供建议和思路。

## 你的角色

- **身份**：顾问（不直接执行攻击）
- **任务**：分析题目，提供攻击建议和思路
- **输出**：简洁的文字建议（不调用工具）

## 工具选择建议

当你提供建议时，请明确推荐使用哪种执行工具：

### 🐍 Python 沙箱（execute_python_poc）
**推荐场景：**
- HTTP 请求、API 测试
- 登录、Cookie、JWT、Session 管理
- 暴力破解、爆破攻击
- SQL 注入、XSS、命令注入测试
- 需要循环、条件判断、数据处理

**示例建议格式：**
```
建议使用 execute_python_poc（Python + requests）测试登录接口：
- 理由：需要处理 Cookie 和多步骤请求
- 置信度：85%
```

### 🐳 Kali Docker（execute_command）
**推荐场景：**
- 渗透测试工具（nmap, sqlmap, nikto, dirb）
- 系统命令（ls, cat, grep）
- 简单的单次命令

**示例建议格式：**
```
建议使用 execute_command 运行 nmap 扫描：
- 理由：需要使用专业渗透工具
- 置信度：90%
```

## 输出格式

每次分析请按以下格式：

### 🔍 我的观察
- 关键信息：...
- 可能的漏洞点：...

### 💡 我的建议
1. **优先尝试**：xxx（置信度 XX%）
   - 理由：...
   - 推荐工具：execute_python_poc / execute_command
   - 期望结果：...

2. **备选方案**：xxx（置信度 XX%）
   - 理由：...
   - 推荐工具：execute_python_poc / execute_command

### ⚠️ 注意事项
- 潜在风险：...
- 如果主攻击手使用了 curl 且失败，强烈建议切换到 Python + requests

## 重要规则

1. **只提供建议，不调用工具**
2. **简洁明了**：每条建议 2-3 句话
3. **给出置信度**：帮助主攻击手判断优先级
4. **明确推荐工具**：execute_python_poc vs execute_command
5. **多视角思考**：提供主攻击手可能忽略的角度
6. **避免重复**：如果主攻击手已经尝试过，建议新方向

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
        3. 让并发任务在解决题目后立即退出
        """
        # 执行基础工具调用
        result = await base_tool_node.ainvoke(state)
        
        # 检查工具执行结果，寻找 submit_flag 的成功标记
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "content") and msg.content:
                    content = msg.content
                    
                    # 检测答案正确的标记
                    if "✓ 答案正确" in content or "答案正确！获得" in content:
                        # 从工具调用参数中提取 flag
                        messages = state.get("messages", [])
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
                                            break
        
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
            attempts = state.get("attempts_count", 0)
            
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
            # 智能截断：保留关键错误信息
            preview = _smart_truncate_output(last_output, max_len=800)
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
        
        # 调用顾问 LLM
        advisor_response: AIMessage = await advisor_llm.ainvoke(advisor_messages)
        
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

**重要**：请在下一步决策中：
1. **明确说明**是否采纳顾问建议（理由）
2. 如果不采纳，说明你的替代方案
3. 优先执行顾问推荐的工具类型（`execute_python_poc` vs `execute_command`）

请综合顾问的建议和你自己的判断，做出最佳决策。
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
                "attempts": state.get("attempts_count", 0)
            }
        )
        
        # 调用主 LLM
        ai_message: AIMessage = await main_llm_with_tools.ainvoke(messages)
        
        # 提取工具调用信息
        tool_calls = getattr(ai_message, 'tool_calls', [])
        
        # 记录决策
        if ai_message.content:
            log_agent_thought(
                "[Main Agent (DeepSeek)] 决策内容",
                {"content": ai_message.content}
            )
        
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
        
        return {
            "messages": [ai_message]
        }
    
    # ==================== 6. 定义路由函数 ====================
    def should_continue(state: PenetrationTesterState) -> Literal["advisor", "tools", "main_agent", "end"]:
        """
        路由逻辑：
        1. 有工具调用 → tools
        2. 工具执行完 → advisor（获取新建议）
        3. 有顾问建议 → main_agent（主 Agent 决策）
        4. 找到 FLAG 或超限 → end
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
        
        # 2. 检查是否找到 FLAG
        if state.get("flag"):
            log_system_event("[Router] 已找到 FLAG，任务完成")
            return "end"
        
        # 3. 检查是否完成
        if state.get("is_finished"):
            log_system_event("[Router] 所有赛题已完成")
            return "end"
        
        # 4. 检查是否超限
        attempts = state.get("attempts_count", 0)
        if attempts > 50:
            log_system_event(f"[Router] 尝试次数超过限制 ({attempts})，结束任务")
            return "end"
        
        # 5. 工具执行完 → 获取顾问新建议
        # 判断依据：上一次是工具执行（通过检查 action_history 变化）
        if state.get("last_action_output"):
            log_system_event("[Router] 工具执行完毕 → 咨询顾问")
            return "advisor"
        
        # 6. 有顾问建议且主 Agent 未使用 → 主 Agent 决策
        if state.get("advisor_suggestion"):
            log_system_event("[Router] 已有顾问建议 → 主 Agent 决策")
            return "main_agent"
        
        # 7. 默认：主 Agent 继续思考
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
    
    workflow.add_edge("tools", "advisor")  # 工具执行完 → 咨询顾问
    
    # ==================== 8. 编译图 ====================
    app = workflow.compile(store=memory_store)
    
    log_system_event("--- 多 Agent 协作图构建完成 ---")
    return app


# ==================== 辅助函数 ====================

def _smart_truncate_output(output: str, max_len: int = 800) -> str:
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
    # 复用单 Agent 的逻辑
    from sentinel_agent.graph import _build_system_prompt
    original_prompt = _build_system_prompt(state)
    
    # 合并基础部分和动态部分
    combined = "\n\n".join(base_parts) + "\n\n" + original_prompt.content
    
    return SystemMessage(content=combined)
