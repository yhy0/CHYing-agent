"""
工具模块
========

导出所有可用的工具函数。

核心理念：
- 提供统一的工具入口
- 工具函数直接返回原始输出，由 LLM 自主决策
- 支持多类工具：Shell 命令、Python PoC、记忆工具
"""
from sentinel_agent.tools.shell import execute_command
from sentinel_agent.tools.shell_enhanced import execute_python_poc
from sentinel_agent.tools.memory_tools import (
    record_vulnerability_discovery,
    record_successful_exploit,
    record_failed_attempt,
    query_historical_knowledge,
    get_memory_tools
)


# 导出所有可用工具
__all__ = [
    "execute_command",
    "execute_python_poc",
    "record_vulnerability_discovery",
    "record_successful_exploit",
    "record_failed_attempt",
    "query_historical_knowledge",
    "get_memory_tools",
]


def get_all_tools():
    """
    获取所有渗透测试工具列表
    
    不包括记忆和比赛工具（这些由 langmem_memory.py 统一管理）
    
    Returns:
        工具函数列表
    """
    return [
        execute_command,
        execute_python_poc,
    ]
