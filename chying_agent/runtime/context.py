"""
题目上下文管理
==============

使用 contextvars 实现协程隔离的上下文管理。
在 asyncio 并发环境中每个协程有独立的上下文。

统一管理：
- challenge_code: 题目代码
- work_dir: 题目工作目录

这两个总是关联在一起，确保题目隔离的一致性。

注意：此模块与 common.py 中的日志上下文不同：
- common.py: 日志文件管理（set_challenge_context/clear_challenge_context）
- 此模块: 题目数据隔离（set_current_challenge_code/get_current_challenge_code/work_dir）
"""

from __future__ import annotations

import contextvars
from pathlib import Path
from typing import Any, Optional, Union


# ==================== 题目隔离上下文 ====================

_current_challenge: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_challenge", default=None
)

_current_work_dir: contextvars.ContextVar[Optional[Path]] = contextvars.ContextVar(
    "current_work_dir", default=None
)

_current_execution_id: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "current_execution_id", default=None
)

# Hint callback: 由 MCPCTFRunner 注入, solver agent 通过 view_hint 工具间接调用
# 类型: async () -> str
_current_hint_callback: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "_current_hint_callback", default=None
)

# Submit flag callback: 由 BaseCTFRunner 注入, solver agent 通过 submit_flag 工具间接调用
# 类型: async (flag: str) -> (bool, str)  — (is_correct, message)
_current_submit_flag_callback: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "_current_submit_flag_callback", default=None
)


# ==================== 设置函数 ====================


def set_current_challenge_code(challenge_code: str) -> None:
    """设置当前协程的题目 challenge_code"""
    _current_challenge.set(challenge_code)


def set_current_work_dir(work_dir: Union[str, Path]) -> None:
    """
    设置当前协程的题目工作目录

    Args:
        work_dir: 工作目录路径
    """
    path = Path(work_dir) if isinstance(work_dir, str) else work_dir
    _current_work_dir.set(path)


def clear_current_challenge_code() -> None:
    """清除当前协程的题目上下文（challenge_code + work_dir）"""
    _current_challenge.set(None)
    _current_work_dir.set(None)


def set_current_execution_id(execution_id: Optional[int]) -> None:
    """设置当前协程的执行 ID（由 ExecutionContext 调用）"""
    _current_execution_id.set(execution_id)


def get_current_execution_id() -> Optional[int]:
    """获取当前协程的执行 ID"""
    return _current_execution_id.get()


# ==================== Hint Callback ====================


def set_hint_callback(cb) -> None:
    """设置当前协程的 hint 回调 (async () -> str)"""
    _current_hint_callback.set(cb)


def get_hint_callback():
    """获取当前协程的 hint 回调, 无则返回 None"""
    return _current_hint_callback.get()


def clear_hint_callback() -> None:
    """清除当前协程的 hint 回调"""
    _current_hint_callback.set(None)


# ==================== Submit Flag Callback ====================


def set_submit_flag_callback(cb) -> None:
    """设置当前协程的 submit_flag 回调 (async (flag: str) -> (bool, str))"""
    _current_submit_flag_callback.set(cb)


def get_submit_flag_callback():
    """获取当前协程的 submit_flag 回调，无则返回 None"""
    return _current_submit_flag_callback.get()


def clear_submit_flag_callback() -> None:
    """清除当前协程的 submit_flag 回调"""
    _current_submit_flag_callback.set(None)


# ==================== 获取函数 ====================


def get_current_challenge_code() -> Optional[str]:
    """获取当前协程的题目 challenge_code"""
    return _current_challenge.get()


def get_current_work_dir() -> Optional[Path]:
    """获取当前协程的题目工作目录"""
    return _current_work_dir.get()


__all__ = [
    # 主要函数
    "set_current_challenge_code",
    "set_current_work_dir",
    "clear_current_challenge_code",
    "get_current_challenge_code",
    "get_current_work_dir",
    # execution_id 上下文
    "set_current_execution_id",
    "get_current_execution_id",
    # hint callback (MCP 比赛模式)
    "set_hint_callback",
    "get_hint_callback",
    "clear_hint_callback",
    # submit_flag callback (MCP 比赛模式)
    "set_submit_flag_callback",
    "get_submit_flag_callback",
    "clear_submit_flag_callback",
]
