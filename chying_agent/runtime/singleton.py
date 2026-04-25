"""
单例模式实现
============

提供全局配置和执行器的单例访问。
"""

from typing import Optional
from threading import RLock

from chying_agent.config import AgentConfig, load_agent_config
from chying_agent.executor.base import BaseExecutor
from chying_agent.executor.factory import get_executor as _get_executor


class ConfigManager:
    """
    配置管理器（单例模式）

    线程安全的配置和执行器管理器。
    """

    _instance: Optional["ConfigManager"] = None
    _lock = RLock()

    def __new__(cls):
        """
        单例模式实现（双重检查锁定）

        Returns:
            ConfigManager 单例实例
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    # 在 __new__ 中完成初始化，避免重复调用 __init__
                    instance._config = None
                    instance._executor = None
                    cls._instance = instance
        return cls._instance

    @property
    def config(self) -> AgentConfig:
        """
        获取配置实例（延迟加载，线程安全）

        Returns:
            AgentConfig 实例
        """
        if self._config is None:
            with self._lock:
                if self._config is None:
                    self._config = load_agent_config()
        return self._config

    @property
    def executor(self) -> BaseExecutor:
        """
        获取执行器实例（延迟加载，线程安全）

        Returns:
            BaseExecutor 实例
        """
        if self._executor is None:
            with self._lock:
                if self._executor is None:
                    # 注意：不要在持有同一把锁时再调用 self.config（会触发递归加锁路径）。
                    # 这里直接初始化 _config，避免首次访问 executor 时出现死锁。
                    if self._config is None:
                        self._config = load_agent_config()
                    self._executor = _get_executor(self._config)
        return self._executor

    def reset(self):
        """
        重置配置（主要用于测试）

        注意：此方法不是线程安全的，仅应在测试环境中使用。
        """
        self._config = None
        self._executor = None


# 全局单例访问函数
def get_config_manager() -> ConfigManager:
    """
    获取配置管理器单例

    Returns:
        ConfigManager 单例实例
    """
    return ConfigManager()
