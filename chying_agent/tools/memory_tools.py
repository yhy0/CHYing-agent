"""
记忆工具定义（基于 LangMem 官方实现）
====================================

使用 LangMem 官方工具实现记忆管理，支持：
- 动态命名空间：每个题目独立的记忆空间
- 向量搜索：语义相似度搜索（需配置 embedding）
- 持久化：通过 LangGraph Store 持久化

题目隔离机制：
- 使用 namespace=("chying_agent", "challenge", "{langgraph_user_id}")
- 运行时通过 config["configurable"]["langgraph_user_id"] = challenge_code 实现隔离
"""
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import logging
import contextvars

from langchain_core.tools import tool
from langmem import create_manage_memory_tool, create_search_memory_tool

from chying_agent.common import log_security_event, log_system_event


# ==================== LangMem 官方工具（动态命名空间）====================
# 使用 {langgraph_user_id} 占位符，运行时通过 config 注入 challenge_code

# 记忆管理工具（创建/更新/删除）
manage_memory = create_manage_memory_tool(
    namespace=("chying_agent", "challenge", "{langgraph_user_id}"),
    instructions="""在以下情况主动调用此工具记录重要发现：

1. 发现关键信息：API 端点、隐藏字段、敏感文件、版本信息
2. 发现可利用漏洞：SQL 注入点、XSS 漏洞、文件包含等
3. 成功的攻击方法：记录有效的 payload 和利用步骤
4. 需要更新或删除过时的记忆

注意：只记录关键发现，不记录失败尝试。""",
    actions_permitted=("create", "update", "delete"),
    name="manage_memory"
)

# 记忆搜索工具（语义搜索）
search_memory = create_search_memory_tool(
    namespace=("chying_agent", "challenge", "{langgraph_user_id}"),
    instructions="""搜索之前记录的发现和攻击方法。

使用场景：
- 回顾已发现的漏洞点
- 查找之前成功的攻击方法
- 检查是否有相关的历史记录""",
    name="search_memory"
)


# ==================== 兼容层：保留原有接口 ====================
# 为了兼容现有代码（challenge_solver.py, graph.py），保留原有函数

# 协程上下文变量（替代 threading.local，在 asyncio 环境中正确隔离）
_current_challenge: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    'current_challenge', default=None
)

# 运行时缓存（兼容层，用于 get_all_discoveries）
_runtime_cache: Dict[str, Dict] = {}


def set_current_challenge(challenge_code: str):
    """
    设置当前协程的题目 challenge_code（在解题开始时调用）

    ⭐ 使用 contextvars.ContextVar 实现协程隔离，
    在 asyncio 并发环境中每个协程有独立的上下文。

    注意：LangMem 工具的题目隔离通过 config["configurable"]["langgraph_user_id"] 实现，
    此函数主要用于兼容 get_all_discoveries() 等旧接口。
    """
    _current_challenge.set(challenge_code)

    # 初始化缓存（兼容旧接口）
    if challenge_code not in _runtime_cache:
        _runtime_cache[challenge_code] = {
            "discoveries": [],
        }
        log_system_event(
            f"[记忆] 为题目 {challenge_code} 初始化记忆空间",
            {"challenge_code": challenge_code}
        )


def get_current_challenge() -> Optional[str]:
    """获取当前协程的题目 challenge_code"""
    return _current_challenge.get()


def get_all_discoveries(challenge_code: str = None) -> List[Dict]:
    """
    获取指定题目的所有记忆（用于 Advisor 读取）

    ⭐ 兼容层：从运行时缓存读取

    注意：此函数返回的是兼容层缓存，不是 LangMem Store 中的数据。
    如需搜索 LangMem 记忆，请使用 search_memory 工具。
    """
    if challenge_code is None:
        challenge_code = get_current_challenge()

    if challenge_code is None:
        log_system_event(
            "[记忆] ⚠️ challenge_code 未设置",
            level=logging.WARNING
        )
        return []

    if challenge_code not in _runtime_cache:
        return []

    return _runtime_cache[challenge_code].get("discoveries", [])


# ==================== 自定义包装工具（同步写入兼容层缓存）====================

@tool
def add_memory(content: str) -> str:
    """
    记录重要发现到记忆中，供 Advisor 参考。

    使用场景（只记录关键发现，不记录失败）：
    - 发现 API 端点、隐藏字段、敏感文件
    - 发现可疑参数、错误信息、版本信息
    - 成功的攻击方法
    - 任何可能有用的线索

    Args:
        content: 要记录的内容（如：发现 /api/edit_profile 端点包含 is_admin 参数）

    Returns:
        记录确认信息

    Examples:
        add_memory("发现 /api/edit_profile 端点包含 is_admin 参数")
        add_memory("表单中发现 hidden 字段：user_role=guest")
        add_memory("成功通过IDOR修改company_id提升为管理员")
    """
    try:
        # 获取当前 challenge_code
        challenge_code = get_current_challenge()

        memory = {
            "content": content,
            "timestamp": datetime.now().isoformat()
        }

        # 写入兼容层缓存（供 get_all_discoveries 使用）
        if challenge_code:
            if challenge_code not in _runtime_cache:
                _runtime_cache[challenge_code] = {"discoveries": []}
            _runtime_cache[challenge_code]["discoveries"].append(memory)

        log_security_event(
            f"[记忆] 添加记忆",
            {**memory, "challenge_code": challenge_code or "unknown"}
        )

        return f"✅ 已记录: {content}"
    except Exception as e:
        log_system_event(
            f"[记忆] ⚠️ 记录失败: {str(e)}",
            level=logging.ERROR
        )
        return f"⚠️ 记录失败: {str(e)}"


# ==================== 工具导出 ====================

# 基础记忆工具（兼容旧代码）
MEMORY_TOOLS = [
    add_memory,
]

# LangMem 官方工具（需要配置 Store 才能使用）
LANGMEM_TOOLS = [
    manage_memory,
    search_memory,
]


def get_memory_tools(use_langmem: bool = False) -> List:
    """
    获取记忆工具列表

    Args:
        use_langmem: 是否使用 LangMem 官方工具（需要配置 Store）

    Returns:
        记忆工具列表
    """
    if use_langmem:
        return LANGMEM_TOOLS
    return MEMORY_TOOLS


def get_langmem_tools() -> Tuple:
    """
    获取 LangMem 官方工具（manage_memory, search_memory）

    Returns:
        (manage_memory, search_memory) 元组

    注意：这些工具需要在 LangGraph 中配置 Store 才能正常工作。
    运行时通过 config["configurable"]["langgraph_user_id"] = challenge_code 实现题目隔离。
    """
    return manage_memory, search_memory
