"""核心模块：常量定义和单例管理"""

from sentinel_agent.core.constants import (
    NodeNames,
    ToolNames,
    PromptTemplates,
    Timeouts,
    RetryConfig,
    LogConfig,
    MemoryConfig
)
from sentinel_agent.core.singleton import get_config_manager

__all__ = [
    "NodeNames",
    "ToolNames",
    "PromptTemplates",
    "Timeouts",
    "RetryConfig",
    "LogConfig",
    "MemoryConfig",
    "get_config_manager"
]
