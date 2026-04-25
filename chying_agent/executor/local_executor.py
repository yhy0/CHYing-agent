"""本地执行器实现（容器内模式）

在容器内用 subprocess 直接执行命令，替代通过 Docker API 远程执行。
保持与 DockerExecutor 相同的接口。
"""

import logging
import os
import signal
import subprocess
import tempfile

from chying_agent.common import log_system_event
from chying_agent.executor.base import BaseExecutor, ExecutionResult


class LocalExecutor(BaseExecutor):
    """在本地（容器内）用 subprocess 执行命令的执行器。

    用于 CHYING_IN_CONTAINER=1 模式，此时程序本身运行在 Kali 容器中，
    不需要通过 Docker API 远程调用。
    """

    def execute(
        self, command: str, timeout: int = 120, is_python: bool = False,
        workdir: str | None = None, caller: str = "",
        environment: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """在本地执行命令，支持超时控制。"""
        tmp_path: str | None = None
        try:
            # 合并环境变量
            merged_env = os.environ.copy()
            if environment:
                merged_env.update(environment)

            if is_python:
                # Python 代码：写临时文件再执行
                tmp_fd, tmp_path = tempfile.mkstemp(suffix=".py", prefix="chying_poc_")
                try:
                    with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                        f.write(command)
                    exec_args = ["python3", tmp_path]
                except Exception:
                    os.close(tmp_fd)
                    raise
            else:
                exec_args = ["/bin/bash", "-c", command]

            # 使用 subprocess.run 的原生超时支持
            try:
                result = subprocess.run(
                    exec_args,
                    capture_output=True,
                    timeout=timeout,
                    cwd=workdir,
                    env=merged_env,
                    # 使用进程组，超时时可以杀死整个子进程树
                    preexec_fn=os.setsid,
                )
            except subprocess.TimeoutExpired as e:
                # 超时：杀死整个进程组
                try:
                    os.killpg(os.getpgid(e.cmd[0] if isinstance(e.cmd, list) else 0), signal.SIGKILL)
                except (ProcessLookupError, OSError, TypeError):
                    pass

                # subprocess.TimeoutExpired 可能携带部分输出
                partial_stdout = (e.stdout or b"").decode("utf-8", errors="ignore")
                partial_stderr = (e.stderr or b"").decode("utf-8", errors="ignore")

                timeout_note = f"命令执行超时（{timeout}秒）。"
                log_system_event(
                    "LocalExecutor.命令超时",
                    {
                        "timeout": timeout,
                        "caller": caller or "unknown",
                        "command": command,
                    },
                    level=logging.WARNING,
                )
                return ExecutionResult(
                    exit_code=-1,
                    stdout=partial_stdout,
                    stderr=partial_stderr + ("\n" if partial_stderr else "") + timeout_note,
                    command=command,
                )

            stdout_str = result.stdout.decode("utf-8", errors="ignore").strip()
            stderr_str = result.stderr.decode("utf-8", errors="ignore").strip()
            exit_code = result.returncode

            log_system_event(
                "LocalExecutor.执行完成",
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
        except Exception as e:
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"本地执行命令时发生错误: {e}",
                command=command,
            )
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
