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
        
        # 提取工具调用信息
        tool_calls = getattr(ai_message, 'tool_calls', [])
        
        # 记录 LLM 输出内容
        if ai_message.content:
            log_agent_thought(
                "[Agent] LLM 输出内容",
                {"content": ai_message.content}
            )
        
        # 记录工具调用详情
        if tool_calls:
            log_agent_thought(
                f"[Agent] 决策：调用 {len(tool_calls)} 个工具",
                {
                    "tools": [
                        {
                            "name": tc.get("name"),
                            "args": tc.get("args", {})
                        }
                        for tc in tool_calls
                    ]
                }
            )
        else:
            log_agent_thought("[Agent] 决策：无工具调用（继续思考）")
        
        return {
            "messages": [ai_message]
        }
    
    # ==================== 6. 定义路由函数（增强版：检测失败模式）====================
    def should_continue(state: PenetrationTesterState) -> Literal["tools", "agent", "end"]:
        """
        判断下一步：调用工具 / 继续思考 / 结束
        
        路由逻辑：
        1. 有工具调用 → tools
        2. 找到 FLAG → end
        3. 所有赛题完成 → end
        4. 检测失败模式（curl 引号错误、重复命令等）→ 在系统提示中警告
        5. 默认 → agent（让 LLM 继续思考）
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
        
        # 4. 检测失败模式（通过分析 action_history）
        action_history = state.get("action_history", [])
        if len(action_history) >= 3:
            # 检测最近 3 次是否都是 curl 命令且失败
            recent_actions = action_history[-3:]
            curl_failures = sum(1 for action in recent_actions if "curl" in str(action).lower() and ("exit code: 2" in str(action).lower() or "unexpected eof" in str(action).lower()))
            
            if curl_failures >= 2:
                log_system_event(
                    "[Router] ⚠️ 检测到失败模式：多次 curl 引号/转义错误，建议切换到 Python",
                    {"curl_failures": curl_failures, "recent_actions": len(recent_actions)}
                )
        
        # 5. 检查是否超过最大尝试次数（提高到 70 次，适应复杂 CTF）
        attempts = state.get("attempts_count", 0)
        if attempts > 70:
            log_system_event(
                f"[Router] 尝试次数超过限制 ({attempts})，结束任务"
            )
            return "end"
        
        # 6. 默认：让 LLM 继续思考（如果没有工具调用，说明需要更多分析）
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
        attempts = state.get("attempts_count", 0)
        
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

