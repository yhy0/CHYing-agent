"""
LangGraph 图构建（重构版 - 符合官方最佳实践）
=======================================

核心理念：
- 采用官方推荐的 **单节点 Agent** 架构
- LLM 自主决策所有流程（无需预定义阶段）
- 完全符合 LangGraph ReAct Pattern

重构日期：2025-11-09
重构原因：旧架构使用 4 个节点（Recon/Analysis/Exploitation/Post-Exploitation）违反 LangGraph 最佳实践
"""
from typing import Literal
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage, AIMessage
from langchain_core.runnables import RunnableConfig

from sentinel_agent.state import PenetrationTesterState
from sentinel_agent.tools import get_all_tools
from sentinel_agent.common import log_system_event, log_agent_thought
from sentinel_agent.langmem_memory import get_memory_store, get_all_memory_tools


async def build_graph(llm_model: BaseChatModel):
    """
    构建 Sentinel Agent（官方推荐的单节点架构）
    
    架构特点：
    1. **单一 Agent 节点** - LLM 自主决策所有行动
    2. **ToolNode 自动处理工具** - 无需手动路由
    3. **LangMem 记忆集成** - 持久化知识
    4. **动态系统提示词** - 根据状态调整引导
    
    工作流程：
    agent → [tools?] → agent → [tools?] → ... → end
    
    Args:
        llm_model: LLM 模型实例
        
    Returns:
        编译后的 LangGraph 应用
    """
    # ==================== 1. 初始化记忆系统 ====================
    memory_store = get_memory_store()
    memory_tools = get_all_memory_tools()
    
    log_system_event(
        "--- 初始化 LangMem 记忆系统 ---", 
        {
            "memory_tools_count": len(memory_tools),
            "store_type": type(memory_store).__name__,
        }
    )
    
    # ==================== 2. 获取所有工具 ====================
    pentest_tools = get_all_tools()
    all_tools = pentest_tools + memory_tools
    
    log_system_event(
        "--- 加载所有工具 ---",
        {
            "pentest_tools": [tool.name for tool in pentest_tools],
            "memory_tools": [tool.name for tool in memory_tools],
            "total_count": len(all_tools)
        }
    )
    
    # ==================== 3. 绑定工具到 LLM ====================
    llm_with_tools = llm_model.bind_tools(all_tools)
    
    # ==================== 4. 创建 ToolNode ====================
    tool_node = ToolNode(all_tools)
    
    # ==================== 5. 定义单一 Agent 节点 ====================
    async def agent_node(state: PenetrationTesterState):
        """
        单一 Agent 节点 - 处理所有决策
        
        LLM 会根据动态系统提示词自主决定：
        - 何时获取赛题（调用 get_challenge_list）
        - 何时开始攻击（调用 execute_command、execute_python_poc）
        - 使用什么工具（curl、sqlmap、Python 脚本等）
        - 何时提交 FLAG（调用 submit_flag）
        - 何时查看提示（调用 view_challenge_hint）
        """
        # 构建动态系统提示词
        system_message = _build_system_prompt(state)
        
        # 获取对话历史
        messages = list(state.get("messages", []))
        
        # 添加或更新系统消息
        if not messages or not isinstance(messages[0], SystemMessage):
            messages.insert(0, system_message)
        else:
            # 更新系统消息（保持最新状态）
            messages[0] = system_message
        
        log_agent_thought(
            "[Agent] 开始思考...",
            {
                "challenges": bool(state.get("challenges")),
                "current_challenge": state.get("current_challenge", {}).get("code") if state.get("current_challenge") else None,
                "attempts": state.get("attempts_count", 0)
            }
        )
        
        # 调用 LLM
        ai_message: AIMessage = await llm_with_tools.ainvoke(messages)
        
        log_agent_thought(
            "[Agent] 决策完成",
            {
                "has_tool_calls": bool(getattr(ai_message, 'tool_calls', [])),
                "tool_count": len(getattr(ai_message, 'tool_calls', [])),
                "content_preview": ai_message.content[:200] if ai_message.content else ""
            }
        )
        
        return {
            "messages": [ai_message]
        }
    
    # ==================== 6. 定义路由函数 ====================
    def should_continue(state: PenetrationTesterState) -> Literal["tools", "agent", "end"]:
        """
        判断下一步：调用工具 / 继续思考 / 结束
        
        路由逻辑：
        1. 有工具调用 → tools
        2. 找到 FLAG → end
        3. 所有赛题完成 → end
        4. 默认 → agent（让 LLM 继续思考）
        """
        messages = state.get("messages", [])
        
        if not messages:
            return "end"
        
        last_message = messages[-1]
        
        # 1. 检查是否有工具调用
        if hasattr(last_message, 'tool_calls') and last_message.tool_calls:
            log_system_event(
                f"[Router] 检测到 {len(last_message.tool_calls)} 个工具调用，转到 ToolNode"
            )
            return "tools"
        
        # 2. 检查是否找到 FLAG
        if state.get("flag"):
            log_system_event("[Router] 已找到 FLAG，任务完成")
            return "end"
        
        # 3. 检查是否所有赛题完成
        if state.get("is_finished"):
            log_system_event("[Router] 所有赛题已完成")
            return "end"
        
        # 4. 检查是否超过最大尝试次数（防止无限循环）
        attempts = state.get("attempts_count", 0)
        if attempts > 20:
            log_system_event(
                f"[Router] 尝试次数超过限制 ({attempts})，结束任务"
            )
            return "end"
        
        # 5. 默认：让 LLM 继续思考（如果没有工具调用，说明需要更多分析）
        log_system_event("[Router] Agent 继续思考...")
        return "agent"
    
    # ==================== 7. 构建 StateGraph ====================
    workflow = StateGraph(PenetrationTesterState)
    
    # 添加节点
    workflow.add_node("agent", agent_node)
    workflow.add_node("tools", tool_node)
    
    # 设置入口
    workflow.set_entry_point("agent")
    
    # 定义边
    workflow.add_conditional_edges(
        "agent",
        should_continue,
        {
            "tools": "tools",
            "agent": "agent",  # 继续思考
            "end": END
        }
    )
    
    # 工具执行后总是返回 agent
    workflow.add_edge("tools", "agent")
    
    # ==================== 8. 编译图 ====================
    app = workflow.compile(store=memory_store)
    
    log_system_event("--- LangGraph 构建完成（单节点 Agent 架构）---")
    return app


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
    remaining = [c for c in challenges if c.get("code") not in completed]
    
    if remaining and not state.get("current_challenge"):
        next_challenge = remaining[0]
        prompt_parts.append(f"""
## 📋 赛题列表（{len(remaining)}/{len(challenges)} 未完成）

**建议攻击赛题：** {next_challenge.get('name')} ({next_challenge.get('code')})
- URL: {next_challenge.get('url')}
- 类型: {next_challenge.get('type')}
- 难度: {next_challenge.get('difficulty')}

请开始攻击此赛题。
""")
        return SystemMessage(content="\n".join(prompt_parts))
    
    # 阶段 3: 正在攻击赛题
    if state.get("current_challenge"):
        challenge = state["current_challenge"]
        attempts = state.get("attempts_count", 0)
        
        prompt_parts.append(f"""
## 🎯 当前攻击中：{challenge.get('name')}

### 赛题信息
- 代码：`{challenge.get('code')}`
- URL：`{challenge.get('url')}`
- 类型：`{challenge.get('type')}`
- 难度：`{challenge.get('difficulty')}`
- 尝试次数：{attempts}

### 攻击策略
1. **信息收集**：
   - 使用 `execute_command` 执行 `curl {challenge.get('url')}` 查看页面
   - 分析响应头、Cookie、隐藏字段
   
2. **漏洞测试**（根据类型）：
   - **SQL注入**：测试输入参数（`' OR '1'='1`）
   - **XSS**：测试输入输出（`<script>alert(1)</script>`）
   - **文件包含**：测试路径参数（`../../../../etc/passwd`）
   - **命令注入**：测试系统命令（`; ls -la`）
   
3. **利用工具**：
   - `execute_command`: 执行 Shell 命令（curl、sqlmap 等）
   - `execute_python_poc`: 执行 Python PoC 代码
   
4. **提取 FLAG**：
   - FLAG 格式通常为 `flag{...}` 或 `FLAG{...}`
   - 找到后使用 `submit_flag` 提交
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

