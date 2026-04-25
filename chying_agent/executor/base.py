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
    def execute(self, command: str, timeout: int = 60, is_python: bool = False,
                workdir: str | None = None, caller: str = "",
                environment: dict[str, str] | None = None) -> ExecutionResult:
        """
        执行一个 shell 命令或 Python 代码。

        Args:
            command: 要执行的命令字符串（Shell 命令或 Python 代码）。
            timeout: 命令执行的超时时间（秒）。
            is_python: 是否作为 Python 代码执行。
            workdir: 命令执行的工作目录。
            caller: 调用方标识（如 "exec[shell]"、"exec[python]"），用于超时日志。
            environment: 注入到执行环境的额外环境变量。

        Returns:
            一个 ExecutionResult 实例，包含执行结果。
        """
        pass
