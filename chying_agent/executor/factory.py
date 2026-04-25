"""
执行器工厂
==========

根据配置返回相应的执行器实例。

执行器类型：
1. DockerExecutor - 在 Kali Linux 容器中执行 Shell 命令（宿主机模式）
2. LocalExecutor - 在容器内本地执行命令（容器内模式）
"""

import logging
from chying_agent.config import AgentConfig
from chying_agent.executor.base import BaseExecutor
from chying_agent.common import log_system_event
from chying_agent.utils.path_utils import is_in_container


def get_executor(config: AgentConfig) -> BaseExecutor:
    """
    根据配置获取Shell命令执行器

    容器内模式（CHYING_IN_CONTAINER=1）：返回 LocalExecutor
    宿主机模式：返回 DockerExecutor（需要 DOCKER_CONTAINER_NAME）
    """
    if is_in_container():
        from chying_agent.executor.local_executor import LocalExecutor

        log_system_event(
            "[ExecutorFactory] 容器内模式，使用 LocalExecutor",
        )
        return LocalExecutor()

    if not config.docker_container_name:
        raise ValueError(
            "未配置 Docker 容器！\n"
            "请在 .env 文件中设置 DOCKER_CONTAINER_NAME=kali-sandbox\n"
            "安全提示：不支持本地执行，所有命令必须在 Docker 容器内运行"
        )

    try:
        from chying_agent.executor.docker_native import DockerExecutor

        log_system_event(
            "[ExecutorFactory] 使用 DockerExecutor（Kali Linux）",
            {"container": config.docker_container_name},
        )
        return DockerExecutor(container_name=config.docker_container_name)
    except Exception as e:
        log_system_event(
            f"[ExecutorFactory] DockerExecutor 初始化失败: {e}", level=logging.ERROR
        )
        raise RuntimeError(
            f"无法创建 Docker 执行器: {e}\n"
            "请确保：\n"
            "1. Docker 已安装并运行\n"
            "2. Kali 容器已启动: docker run -d --name kali-sandbox kalilinux/kali-rolling tail -f /dev/null\n"
            "3. Python docker 库已安装: pip install docker"
        ) from e


def get_python_executor(config: AgentConfig) -> BaseExecutor:
    """
    获取 Python 代码执行器

    容器内模式：直接使用 LocalExecutor（已支持 is_python）
    宿主机模式：使用 DockerPythonExecutor 包装 DockerExecutor
    """
    if is_in_container():
        return get_executor(config)

    from chying_agent.executor.docker_python_wrapper import DockerPythonExecutor
    from chying_agent.executor.docker_native import DockerExecutor

    docker_executor = get_executor(config)

    if not isinstance(docker_executor, DockerExecutor):
        raise RuntimeError("get_executor 应返回 DockerExecutor 实例")

    return DockerPythonExecutor(docker_executor)
