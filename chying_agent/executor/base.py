"""执行器基类定义"""
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class ExecutionResult:
    """命令执行结果的统一数据结构"""
    exit_code: int
    stdout: str
    stderr: str
    command: str

class BaseExecutor(ABC):
    """执行器抽象基类"""

    @abstractmethod
    def execute(self, command: str, timeout: int = 60) -> ExecutionResult:
        """
        执行一个 shell 命令。

        Args:
            command: 要执行的命令字符串。
            timeout: 命令执行的超时时间（秒）。

        Returns:
            一个 ExecutionResult 实例，包含执行结果。
        """
        pass
