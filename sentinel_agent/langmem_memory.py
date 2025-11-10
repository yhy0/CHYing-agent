"""
基于 LangMem 的持久化记忆系统
==============================

为 Sentinel Agent 提供长期记忆能力。

功能：
- 向量存储支持
- 持久化检查点
- LangMem 原生工具集成
"""
import os
from typing import Optional, Tuple, List
from langgraph.store.memory import InMemoryStore
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langmem import create_manage_memory_tool, create_search_memory_tool

from sentinel_agent.common import log_system_event
from sentinel_agent.core.constants import MemoryConfig

# 项目根目录
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# SQLite 数据库路径
MEMORY_DB_PATH = os.path.join(PROJECT_ROOT, ".apt_memory.db")
CHECKPOINT_DB_PATH = os.path.join(PROJECT_ROOT, ".apt_checkpoint.db")

# 全局存储实例
_memory_store: Optional[InMemoryStore] = None
_checkpointer: Optional[AsyncSqliteSaver] = None

# LangMem 工具实例
_manage_memory_tool = None
_search_memory_tool = None


def get_memory_store() -> InMemoryStore:
    """
    获取或创建内存存储实例，支持向量搜索
    
    Returns:
        InMemoryStore 实例，配置了向量嵌入支持
    """
    global _memory_store
    if _memory_store is None:
        # 暂时禁用向量搜索，避免需要 OpenAI API Key
        # TODO: 配置 OpenAI API Key 后可启用向量搜索
        _memory_store = InMemoryStore()
        log_system_event("[LangMem] 初始化内存存储（向量搜索已禁用，如需启用请配置 OPENAI_API_KEY）")
    return _memory_store


async def get_checkpointer():
    """
    获取或创建 SQLite checkpointer (作为异步上下文管理器)
    
    Returns:
        AsyncSqliteSaver 异步上下文管理器
    """
    log_system_event(f"[LangMem] 创建 SQLite checkpointer: {CHECKPOINT_DB_PATH}")
    # 返回异步上下文管理器，使用方需要 async with
    return AsyncSqliteSaver.from_conn_string(CHECKPOINT_DB_PATH)


def get_langmem_tools(namespace: Tuple[str, ...] = ("sentinel_agent", "memories")):
    """
    获取 LangMem 原生记忆管理工具
    
    Args:
        namespace: 记忆命名空间，用于组织不同类型的记忆
        
    Returns:
        (manage_memory_tool, search_memory_tool) 元组
    """
    global _manage_memory_tool, _search_memory_tool
    
    if _manage_memory_tool is None or _search_memory_tool is None:
        _manage_memory_tool = create_manage_memory_tool(namespace=namespace)
        _search_memory_tool = create_search_memory_tool(namespace=namespace)
        log_system_event(f"[LangMem] 创建记忆管理工具，命名空间: {namespace}")
    
    return _manage_memory_tool, _search_memory_tool


def get_all_memory_tools() -> List:
    """
    获取所有记忆相关工具的列表
    
    包括：
    - LangMem 原生工具（自动记忆管理）
    - 自定义记忆工具（结构化记录）
    - 比赛 API 工具
    
    注意：不包括 execute_command，该工具由 get_all_tools() 提供
    
    Returns:
        所有工具的列表
    """
    from sentinel_agent.tools.competition_api_tools import get_competition_tools
    from sentinel_agent.tools.memory_tools import get_memory_tools

    # LangMem 原生工具
    manage_tool, search_tool = get_langmem_tools()
    
    # 比赛 API 工具
    competition_tools = get_competition_tools()
    
    # 自定义记忆工具
    memory_tools = get_memory_tools()

    return [
        # LangMem 原生工具（自动记忆管理）
        manage_tool,
        search_tool,
        # 自定义记忆工具（结构化记录）
        *memory_tools,
        # 比赛 API 工具
        *competition_tools,
    ]


def get_memory_db_paths() -> dict:
    """
    获取记忆数据库路径
    
    Returns:
        包含数据库路径的字典
    """
    return {
        "memory_db_path": MEMORY_DB_PATH,
        "checkpoint_db_path": CHECKPOINT_DB_PATH
    }
