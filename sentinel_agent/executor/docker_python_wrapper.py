"""Docker Python 执行器包装器

将 DockerExecutor 包装为 Python 代码执行器，
通过设置 is_python=True 标志来执行 Python 代码。
"""
from sentinel_agent.executor.base import BaseExecutor, ExecutionResult
from sentinel_agent.executor.docker_native import DockerExecutor


class DockerPythonExecutor(BaseExecutor):
    """Docker Python 执行器包装类"""
    
    def __init__(self, docker_executor: DockerExecutor):
        """
        Args:
            docker_executor: DockerExecutor 实例
        """
        self.docker_executor = docker_executor
    
    def execute(self, command: str, timeout: int = 120) -> ExecutionResult:
        """
        执行 Python 代码
        
        Args:
            command: Python 代码字符串
            timeout: 超时时间（秒）
            
        Returns:
            ExecutionResult 实例
        """
        return self.docker_executor.execute(command, timeout=timeout, is_python=True)
