"""
记忆工具定义
============

提供结构化的记忆记录工具，用于记录漏洞发现、成功利用和失败尝试。
"""
from typing import List, Dict
from datetime import datetime
import logging
from langchain_core.tools import tool

from sentinel_agent.common import log_security_event, log_system_event


# 运行时缓存（用于单次运行内的快速访问）
# ⭐ 改进：使用字典隔离不同题目的记忆，避免串题
# 格式：{challenge_code: {"discoveries": [], "attack_paths": [], "failed_attempts": []}}
_runtime_cache = {}

# ⭐ 线程安全改进：使用线程本地存储，避免多线程环境下的记忆串题
import threading
_thread_local = threading.local()


def set_current_challenge(challenge_code: str):
    """
    设置当前线程的题目 challenge_code（在解题开始时调用）

    ⭐ 线程安全：使用 threading.local() 存储，每个线程独立
    """
    _thread_local.challenge_code = challenge_code

    # 如果该题目还没有缓存，初始化（使用锁保护）
    if challenge_code not in _runtime_cache:
        # 简单的初始化，不需要锁（字典操作在 CPython 中是原子的）
        _runtime_cache[challenge_code] = {
            "discoveries": [],
            "attack_paths": [],
            "failed_attempts": []
        }
        log_system_event(
            f"[记忆] 为题目 {challenge_code} 初始化独立记忆空间",
            {"challenge_code": challenge_code, "thread_id": threading.current_thread().name}
        )


def _get_current_cache(challenge_code: str = None) -> Dict:
    """
    获取指定题目的缓存（带异常处理）

    Args:
        challenge_code: 题目代码，如果为 None 则从线程本地存储读取

    Returns:
        题目的记忆缓存字典
    """
    # 优先使用传入的 challenge_code，否则从线程本地存储读取
    if challenge_code is None:
        challenge_code = getattr(_thread_local, 'challenge_code', None)

    if challenge_code is None:
        log_system_event(
            "[记忆] ⚠️ 当前 challenge_code 未设置，使用默认缓存",
            {"thread_id": threading.current_thread().name},
            level=logging.WARNING
        )
        # 使用默认缓存（向后兼容）
        if "default" not in _runtime_cache:
            _runtime_cache["default"] = {
                "discoveries": [],
                "attack_paths": [],
                "failed_attempts": []
            }
        return _runtime_cache["default"]

    # 确保缓存存在
    if challenge_code not in _runtime_cache:
        _runtime_cache[challenge_code] = {
            "discoveries": [],
            "attack_paths": [],
            "failed_attempts": []
        }

    return _runtime_cache[challenge_code]


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

    ⭐ 线程安全：自动从线程本地存储读取 challenge_code
    """
    try:
        memory = {
            "content": content,
            "timestamp": datetime.now().isoformat()
        }

        # ⭐ 使用隔离的缓存（自动从线程本地存储读取 challenge_code）
        cache = _get_current_cache()
        cache["discoveries"].append(memory)

        # 获取当前 challenge_code 用于日志
        current_code = getattr(_thread_local, 'challenge_code', 'unknown')

        log_security_event(
            f"[记忆] 添加记忆",
            {**memory, "challenge_code": current_code}
        )

        return f"✅ 已记录: {content}"
    except Exception as e:
        log_system_event(
            f"[记忆] ⚠️ 记录失败: {str(e)}",
            level=logging.ERROR
        )
        return f"⚠️ 记录失败: {str(e)}"


# ==================== 缓存管理函数 ====================

def get_all_discoveries(challenge_code: str = None) -> List[Dict]:
    """
    获取指定题目的所有记忆（用于 Advisor 读取）

    Args:
        challenge_code: 题目代码，如果为 None 则从线程本地存储读取

    Returns:
        记忆列表

    ⭐ 线程安全：支持显式传递 challenge_code，避免多线程环境下的记忆串题
    """
    try:
        cache = _get_current_cache(challenge_code)
        return cache["discoveries"]
    except Exception as e:
        log_system_event(
            f"[记忆] ⚠️ 获取记忆列表失败: {str(e)}",
            {"challenge_code": challenge_code},
            level=logging.ERROR
        )
        return []


# 导出所有记忆工具
MEMORY_TOOLS = [
    add_memory
]


def get_memory_tools() -> List:
    """获取所有记忆工具"""
    return MEMORY_TOOLS
