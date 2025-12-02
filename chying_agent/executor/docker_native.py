"""Docker 执行器实现（传统方案，用于 Kali Linux 等镜像）"""

# 注意: 此模块依赖 `docker` Python 库。
# 请通过 `pip install docker` 进行安装。

try:
    import docker
    from docker.errors import DockerException, NotFound
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None
    DockerException = Exception
    NotFound = Exception

from chying_agent.executor.base import BaseExecutor, ExecutionResult
from chying_agent.common import log_system_event
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from functools import partial


class DockerExecutor(BaseExecutor):
    """
    在指定的 Docker 容器内执行 Shell 命令的执行器。
    提供了安全的沙箱环境，适合运行 Kali Linux 等渗透测试工具。
    
    使用场景：
    - 执行 nmap、metasploit 等渗透测试工具
    - 需要完整的 Linux 环境和工具链
    - 执行原生 Shell 命令
    """

    def __init__(self, container_name: str):
        """
        初始化 DockerExecutor。
        
        Args:
            container_name: 目标 Docker 容器的名称或ID。
        """
        if not DOCKER_AVAILABLE:
            raise ImportError(
                "Docker 库未安装。请运行: pip install docker"
            )
        
        self.container_name = container_name
        try:
            self.client = docker.from_env()
            self.container = self.client.containers.get(self.container_name)
            # 这个日志不记录了，避免日志过多，只记录失败的
            # log_system_event(
            #     f"[Executor] 成功连接到 Docker 容器 '{self.container_name}'", 
            #     {"container_id": self.container.short_id}
            # )
        except Exception as e:
            log_system_event(
                f"[Executor] 无法连接到 Docker 容器 '{self.container_name}'", 
                {"error": str(e)}, 
                level=logging.ERROR
            )
            raise ConnectionError(
                f"无法找到或连接到名为 '{self.container_name}' 的 Docker 容器。"
                f"请确保容器正在运行。提示：docker ps"
            ) from e

    def execute(self, command: str, timeout: int = 120, is_python: bool = False) -> ExecutionResult:
        """
        在 Docker 容器内执行命令（同步接口，支持超时控制）。
        
        Args:
            command: 要执行的命令字符串（Shell 命令或 Python 代码）。
            timeout: 命令执行的超时时间（秒）。
            is_python: 是否作为 Python 代码执行。

        Returns:
            一个 ExecutionResult 实例。
        """
        try:
            # 构建执行命令
            if is_python:
                # Python 代码：写入临时文件再执行（避免转义问题）
                import base64
                encoded_code = base64.b64encode(command.encode('utf-8')).decode('ascii')
                exec_cmd = f'/bin/bash -c "echo {encoded_code} | base64 -d | python3"'
            else:
                # Shell 命令：使用单引号避免转义问题
                # 替换单引号为 '\''（正确的 bash 转义方式）
                escaped_command = command.replace("'", "'\\''")
                exec_cmd = f"/bin/bash -c '{escaped_command}'"
            
            # 使用线程池执行阻塞的 Docker API 调用，支持超时
            executor_pool = ThreadPoolExecutor(max_workers=1)
            exec_func = partial(
                self.container.exec_run,
                cmd=exec_cmd,
                demux=True
            )
            
            # 使用 Future 实现超时
            future = executor_pool.submit(exec_func)
            try:
                exec_result = future.result(timeout=timeout)
            except TimeoutError:
                log_system_event(
                    f"[Executor] 命令执行超时（{timeout}秒）",
                    {"command": command},
                    level=logging.WARNING
                )
                return ExecutionResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"命令执行超时（{timeout}秒）。建议使用更快的扫描参数或增加超时时间。",
                    command=command,
                )
            
            exit_code = exec_result.exit_code
            stdout, stderr = exec_result.output
            
            # 解码输出
            stdout_str = stdout.decode('utf-8', errors='ignore').strip() if stdout else ""
            stderr_str = stderr.decode('utf-8', errors='ignore').strip() if stderr else ""
            
            # 记录执行结果
            log_system_event(
                "[Executor] Docker 命令执行结果",
                {
                    "exit_code": exit_code,
                    "stdout_preview": stdout_str if stdout_str else "(空)",
                    "stderr_preview": stderr_str if stderr_str else "(空)",
                    "stdout_length": len(stdout_str),
                    "stderr_length": len(stderr_str)
                }
            )

            return ExecutionResult(
                exit_code=exit_code if exit_code is not None else -1,
                stdout=stdout_str,
                stderr=stderr_str,
                command=command,
            )
        except DockerException as e:
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"在容器 '{self.container_name}' 中执行命令时发生 Docker 异常: {str(e)}",
                command=command,
            )
        except Exception as e:
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"在容器 '{self.container_name}' 中执行命令时发生未知错误: {str(e)}",
                command=command,
            )
