"""
运行时模块
==========

提供运行时上下文管理和配置单例。

- context.py: 协程隔离的上下文管理（challenge_code, work_dir, execution_id）
- singleton.py: 配置管理器单例
"""

from chying_agent.runtime.singleton import get_config_manager
from chying_agent.runtime.context import (
    set_current_challenge_code,
    set_current_work_dir,
    clear_current_challenge_code,
    get_current_challenge_code,
    get_current_work_dir,
    set_current_execution_id,
    get_current_execution_id,
)

__all__ = [
    # singleton
    "get_config_manager",
    # context
    "set_current_challenge_code",
    "set_current_work_dir",
    "clear_current_challenge_code",
    "get_current_challenge_code",
    "get_current_work_dir",
    "set_current_execution_id",
    "get_current_execution_id",
]
