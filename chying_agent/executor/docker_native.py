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
        self._executor_pool = ThreadPoolExecutor(max_workers=4)
        try:
            self.client = docker.from_env()
            self.container = self.client.containers.get(self.container_name)
        except Exception as e:
            log_system_event(
                f"Executor.连接失败",
                {"container": self.container_name, "error": str(e)},
                level=logging.ERROR
            )
            raise ConnectionError(
                f"无法找到或连接到名为 '{self.container_name}' 的 Docker 容器。"
                f"请确保容器正在运行。提示：docker ps"
            ) from e

    def _kill_exec_process(self, exec_id_holder: list[str]) -> None:
        """超时后杀死容器内的 exec 进程，防止僵尸进程累积。"""
        if not exec_id_holder:
            return
        try:
            inspect_result = self.container.client.api.exec_inspect(exec_id_holder[0])
            pid = inspect_result.get("Pid", 0)
            if pid and pid > 0:
                self.container.exec_run(f"kill -9 {pid}", detach=True)
                log_system_event(
                    "Executor.超时进程已杀死",
                    {"pid": pid, "exec_id": exec_id_holder[0]},
                )
        except Exception as e:
            log_system_event(
                "Executor.超时进程清理失败",
                {"error": str(e)},
                level=logging.DEBUG,
            )

    def execute(
        self, command: str, timeout: int = 120, is_python: bool = False,
        workdir: str | None = None, caller: str = "",
        environment: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """
        在 Docker 容器内执行命令（同步接口，支持超时控制，超时后保留部分输出）。

        Args:
            command: 要执行的命令字符串（Shell 命令或 Python 代码）。
            timeout: 命令执行的超时时间（秒）。
            is_python: 是否作为 Python 代码执行。
            workdir: 命令执行的工作目录（容器内路径），如 /root/agent-work/ctf/Web/xxx
            caller: 调用方标识（如 "exec[shell]"、"exec[python]"），用于超时日志。

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

            # 流式读取：在外层定义收集列表，线程写入的部分输出在超时后可直接读取
            stdout_parts: list[str] = []
            stderr_parts: list[str] = []
            # 用于获取 exit_code 的 exec instance ID
            exec_id_holder: list[str] = []

            def _run_streaming():
                """在线程中流式执行并收集输出（低级 API：exec_create + exec_start）"""
                api = self.container.client.api
                exec_instance = api.exec_create(
                    self.container.id, cmd=exec_cmd, workdir=workdir,
                    stdout=True, stderr=True,
                    environment=environment,
                )
                eid = exec_instance["Id"]
                exec_id_holder.append(eid)

                output_gen = api.exec_start(eid, stream=True, demux=True)
                for stdout_chunk, stderr_chunk in output_gen:
                    if stdout_chunk:
                        stdout_parts.append(stdout_chunk.decode('utf-8', errors='ignore'))
                    if stderr_chunk:
                        stderr_parts.append(stderr_chunk.decode('utf-8', errors='ignore'))

            future = self._executor_pool.submit(_run_streaming)
            try:
                future.result(timeout=timeout)
            except TimeoutError:
                self._kill_exec_process(exec_id_holder)

                partial_stdout = "".join(stdout_parts)
                partial_stderr = "".join(stderr_parts)
                timeout_note = f"命令执行超时（{timeout}秒）。"
                if partial_stdout or partial_stderr:
                    timeout_note += "\n以下是超时前捕获的部分输出。"
                log_system_event(
                    "Executor.命令超时",
                    {
                        "timeout": timeout,
                        "caller": caller or "unknown",
                        "command": command,
                        "partial_stdout_len": len(partial_stdout),
                        "partial_stderr_len": len(partial_stderr),
                    },
                    level=logging.WARNING,
                )
                return ExecutionResult(
                    exit_code=-1,
                    stdout=partial_stdout,
                    stderr=partial_stderr + ("\n" if partial_stderr else "") + timeout_note,
                    command=command,
                )

            # 正常完成：从收集的 parts 组装输出
            stdout_str = "".join(stdout_parts).strip()
            stderr_str = "".join(stderr_parts).strip()

            # 通过低级 API exec_inspect 获取真实 exit_code
            exit_code = -1
            if exec_id_holder:
                try:
                    inspect_result = self.container.client.api.exec_inspect(exec_id_holder[0])
                    exit_code = inspect_result.get("ExitCode", -1)
                    if exit_code is None:
                        exit_code = -1
                except Exception:
                    pass

            # 记录执行结果
            log_system_event(
                "Executor.执行完成",
                {
                    "exit_code": exit_code,
                    "stdout_len": len(stdout_str),
                    "stderr_len": len(stderr_str),
                }
            )

            return ExecutionResult(
                exit_code=exit_code,
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
