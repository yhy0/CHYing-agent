"""
基于 LangMem 的持久化记忆系统
==============================

为 CHYing Agent 提供长期记忆能力。

功能：
- 向量存储支持（需配置 embedding）
- 持久化检查点
- 题目隔离（通过动态命名空间）

题目隔离机制：
- LangMem 工具使用 namespace=("chying_agent", "challenge", "{langgraph_user_id}")
- 运行时通过 config["configurable"]["langgraph_user_id"] = challenge_code 实现隔离
"""
import os
from typing import Optional, List
from langgraph.store.memory import InMemoryStore
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from chying_agent.common import log_system_event

# 项目根目录
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# SQLite 数据库路径
MEMORY_DB_PATH = os.path.join(PROJECT_ROOT, ".apt_memory.db")
CHECKPOINT_DB_PATH = os.path.join(PROJECT_ROOT, ".apt_checkpoint.db")

# 全局存储实例
_memory_store: Optional[InMemoryStore] = None


def get_memory_store() -> InMemoryStore:
    """
    获取或创建内存存储实例

    Returns:
        InMemoryStore 实例

    注意：
    - 向量搜索需要配置 OPENAI_API_KEY
    - 如需启用向量搜索，可配置 index 参数
    """
    global _memory_store
    if _memory_store is None:
        # 检查是否配置了 OpenAI API Key（用于向量搜索）
        openai_key = os.getenv("OPENAI_API_KEY")
        if openai_key:
            # 启用向量搜索
            _memory_store = InMemoryStore(
                index={
                    "dims": 1536,
                    "embed": "openai:text-embedding-3-small",
                }
            )
            log_system_event("[LangMem] 初始化内存存储（向量搜索已启用）")
        else:
            # 不启用向量搜索
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


def get_all_memory_tools(manual_mode: bool = False) -> List:
    """
    获取所有记忆相关工具的列表

    包括：
    - 自定义记忆工具（结构化记录，题目隔离）
    - 比赛 API 工具（仅在非手动模式下）

    Args:
        manual_mode: 是否为手动模式（单目标模式）。
                     手动模式下不包含比赛 API 工具（submit_flag 等）

    注意：
    - 不包括 execute_command，该工具由 get_all_tools() 提供
    - LangMem 官方工具通过 get_memory_tools(use_langmem=True) 获取

    Returns:
        所有工具的列表
    """
    from chying_agent.tools.memory_tools import get_memory_tools

    # 自定义记忆工具（题目隔离）
    memory_tools = get_memory_tools()

    # ⭐ 手动模式下不包含比赛 API 工具
    if manual_mode:
        log_system_event("[LangMem] 手动模式：跳过比赛 API 工具（submit_flag 等）")
        return [
            *memory_tools,
        ]

    # 比赛模式：包含比赛 API 工具
    from chying_agent.tools.competition_api_tools import get_competition_tools
    competition_tools = get_competition_tools()

    return [
        # 自定义记忆工具（结构化记录，题目隔离）
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
