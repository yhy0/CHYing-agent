"""
智能失败检测模块
=====================================

使用 LLM 进行语义层面的失败检测，避免简单关键字匹配的局限性。

作者：CHYing
日期：2025-11-11
"""
import logging
from typing import Tuple
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage

from chying_agent.common import log_system_event
from chying_agent.utils.util import retry_llm_call


# ==================== 配置：跳过智能检测的工具白名单 ====================
# 这些工具有明确的成功/失败标识，不需要 LLM 语义检测
SKIP_DETECTION_TOOLS = {
    "submit_flag",           # 已有 flag_validator 验证，返回明确的"答案正确"/"答案错误"
    "get_challenge_list",    # API 调用，HTTP 状态码足够判断成功/失败
    "view_challenge_hint",   # API 调用，返回格式固定
}


async def detect_failure_with_llm(
    tool_output: str,
    tool_name: str = "unknown",
    llm: BaseChatModel = None,
    limiter = None
) -> Tuple[bool, str, str]:
    """
    使用 LLM 进行语义层面的失败检测，并提取关键信息

    Args:
        tool_output: 工具输出内容
        tool_name: 工具名称
        llm: 用于判断的 LLM
        limiter: 速率限制器

    Returns:
        (is_failure, reason, key_info): 是否失败、失败原因/成功总结、关键信息摘要

    设计理念：
        - 如果成功：key_info 包含关键发现（如发现的漏洞、获取的数据等）
        - 如果失败：reason 说明失败原因，key_info 补充上下文
        - 无论成败，都保留关键信息供 Agent 决策
    """
    if llm is None:
        raise ValueError("必须提供 LLM 实例")

    # 构建判断提示词（重点：要求提取关键信息）
    detection_prompt = f"""你是一个安全测试结果分析专家。请分析以下工具执行输出，判断操作是否失败，并提取关键信息。

**工具名称**: {tool_name}

**输出内容**:
```
{tool_output}  
```

**分析任务**:
1. 判断操作是否失败
   - 认证/授权失败：登录失败、密码错误、未授权访问、需要认证等
   - HTTP错误：4xx/5xx状态码、错误响应
   - 业务逻辑失败：虽然HTTP 200但内容包含错误提示（如"Incorrect"、"Failed"、alert-danger等）
   - 执行错误：命令执行失败、异常、超时等

2. 提取关键信息（无论成败都要提取）
   - 成功时：发现的漏洞、获取的数据、暴露的接口、可利用的信息等
   - 失败时：错误类型、阻塞原因、需要的前置条件等

**输出格式**（严格遵守，用---分隔）:
第一行：SUCCESS 或 FAILURE
第二行：---
第三行及之后：关键信息摘要（3-5个要点，每行一个，用 • 开头）

**示例1（失败）**:
FAILURE
---
• 登录失败，返回"Incorrect username or password"
• 需要有效的用户名和密码
• 可能需要先进行用户名枚举

**示例2（成功）**:
SUCCESS
---
• 成功获取API文档，发现3个未授权端点
• 端点路径：/api/users, /api/admin, /api/config
• 返回了用户列表，包含5个用户账号
• 发现admin用户，可能存在权限提升漏洞

现在请分析上述输出："""

    try:
        # 调用 LLM 进行判断（使用速率限制）
        if limiter:
            response = await retry_llm_call(
                llm.ainvoke,
                [HumanMessage(content=detection_prompt)],
                limiter=limiter,
                max_retries=2  # 失败检测可以快速失败
            )
        else:
            response = await llm.ainvoke([HumanMessage(content=detection_prompt)])

        result = response.content.strip()
        
        # 解析结果（格式：状态 + --- + 关键信息）
        parts = result.split('---', 1)
        status_line = parts[0].strip()
        key_info = parts[1].strip() if len(parts) > 1 else "无关键信息提取"

        is_failure = status_line.upper() == "FAILURE"
        
        # reason 用于简短描述（从关键信息中提取第一条）
        key_lines = [line.strip() for line in key_info.split('\n') if line.strip()]
        reason = key_lines[0].lstrip('•').strip() if key_lines else ("失败" if is_failure else "成功")

        log_system_event(
            f"[智能失败检测] {tool_name} → {'❌ 失败' if is_failure else '✅ 成功'}",
            {
                "tool": tool_name,
                "is_failure": is_failure,
                "reason": reason,
                "key_info": key_info
            }
        )

        return is_failure, reason, key_info

    except Exception as e:
        log_system_event(
            f"[智能失败检测] ⚠️ LLM判断失败，回退到关键字检测",
            {"error": str(e)},
            level=logging.WARNING
        )
        # 回退到基础关键字检测
        is_fail, reason = _fallback_keyword_detection(tool_output)
        return is_fail, reason, ""  # 关键字检测不提取信息


def _fallback_keyword_detection(tool_output: str) -> Tuple[bool, str]:
    """
    回退方案：基于关键字的失败检测

    注意：这是简化版本，不提取关键信息（仅用于 LLM 调用失败时的回退）

    Args:
        tool_output: 工具输出内容

    Returns:
        (is_failure, reason): 是否失败以及失败原因
    """
    # ⭐ 特殊检测：捕获"使用 execute_command 调用 submit_flag"的错误
    if "submit_flag: command not found" in tool_output:
        return True, (
            "❌ 错误：submit_flag 是 LangChain 工具，不是 shell 命令！\n"
            "请直接调用 submit_flag 工具，不要通过 execute_command 执行。\n"
            "正确用法：submit_flag(challenge_code='xxx', flag='FLAG{...}')"
        )

    # 明显的错误关键字（优先级高）
    critical_failures = [
        ("exception", "发现异常"),
        ("error:", "命令执行错误"),
        ("failed:", "操作失败"),
        ("command not found", "命令未找到"),
        ("bash:", "Bash脚本错误"),
        ("timeout", "连接超时"),
        ("timed out", "操作超时"),
        ("connecttimeout", "连接超时"),
        ("connectionerror", "连接错误"),
        ("connection refused", "连接被拒绝"),
        ("max retries exceeded", "重试次数超限"),
        ("errno 110", "连接超时 (Errno 110)"),
    ]

    # 检查明显错误
    for keyword, reason in critical_failures:
        if keyword in tool_output.lower():
            return True, reason

    # 业务逻辑失败关键字
    business_failures = [
        "error", "failed", "无法", "错误", "失败",
        "not found", "denied", "incorrect", "unauthorized",
        "alert-danger", "not authenticated", "invalid credentials",
        "permission denied", "access denied", "authentication failed"
    ]

    # 检查业务逻辑失败
    content_lower = tool_output.lower()
    if any(kw in content_lower for kw in business_failures):
        return True, "关键字匹配检测到失败"

    return False, "关键字检测无异常"


def detect_failure_hybrid(
    tool_output: str,
    tool_name: str = "unknown",
    enable_llm: bool = True,
    llm: BaseChatModel = None,
    limiter = None
) -> Tuple[bool, str]:
    """
    混合检测方案：优先使用关键字快速检测，模糊情况交给 LLM

    Args:
        tool_output: 工具输出内容
        tool_name: 工具名称
        enable_llm: 是否启用 LLM 检测
        llm: LLM 实例
        limiter: 速率限制器

    Returns:
        (is_failure, reason): 是否失败以及失败原因
    """
    # 第一阶段：快速关键字检测（明显的失败）
    critical_failures = [
        ("exception", "发现异常"),
        ("error:", "命令执行错误"),
        ("failed:", "操作失败"),
        ("command not found", "命令未找到"),
    ]

    for keyword, reason in critical_failures:
        if keyword in tool_output.lower():
            log_system_event(
                f"[混合检测] {tool_name} → ❌ 明显失败（关键字）",
                {"reason": reason}
            )
            return True, reason

    # 第二阶段：如果没有明显错误，且启用了 LLM，交给 LLM 判断
    if enable_llm and llm:
        # 这里需要在异步上下文中调用，所以先返回一个特殊标记
        # 调用方需要在异步环境中处理
        return None, "需要LLM判断"  # 返回None表示需要进一步LLM判断

    # 第三阶段：LLM未启用，使用完整关键字检测
    return _fallback_keyword_detection(tool_output)
