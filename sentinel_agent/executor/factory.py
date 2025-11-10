"""
执行器工厂
==========

根据配置返回相应的执行器实例。

执行器类型：
1. DockerExecutor - 在 Kali Linux 容器中执行 Shell 命令
2. MicrosandboxExecutor - 在隔离沙箱中执行 Python 代码

优化说明：
- 移除了 @lru_cache 装饰器（因为配置对象是单例，不需要缓存）
- 如果需要单例模式，应在调用层实现
"""
import logging
from sentinel_agent.config import AgentConfig
from sentinel_agent.executor.base import BaseExecutor
from sentinel_agent.common import log_system_event


def get_executor(config: AgentConfig) -> BaseExecutor:
    """
    根据配置获取Shell命令执行器（用于 Kali 工具）
    
    要求：
    - 必须配置 DOCKER_CONTAINER_NAME
    - 不支持本地执行（安全考虑）
    
    Args:
        config: Agent 配置实例
        
    Returns:
        DockerExecutor 实例
        
    Raises:
        ValueError: 如果未配置 Docker 容器
    """
    if not config.docker_container_name:
        raise ValueError(
            "未配置 Docker 容器！\n"
            "请在 .env 文件中设置 DOCKER_CONTAINER_NAME=kali-sandbox\n"
            "安全提示：不支持本地执行，所有命令必须在 Docker 容器内运行"
        )
    
    try:
        from sentinel_agent.executor.docker_native import DockerExecutor
        log_system_event(
            "[ExecutorFactory] 使用 DockerExecutor（Kali Linux）", 
            {"container": config.docker_container_name}
        )
        return DockerExecutor(container_name=config.docker_container_name)
    except Exception as e:
        log_system_event(
            f"[ExecutorFactory] DockerExecutor 初始化失败: {e}",
            level=logging.ERROR
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
    获取 Python 代码执行器（用于 LLM 生成的 PoC）
    
    优先使用 Microsandbox，如果未启用则使用 DockerExecutor（带 Python 支持）
    
    Args:
        config: Agent 配置实例
        
    Returns:
        MicrosandboxExecutor 或 DockerExecutor 实例
    """
    if config.sandbox_enabled:
        try:
            from sentinel_agent.executor.microsandbox import MicrosandboxExecutor
            log_system_event(
                "[ExecutorFactory] 使用 MicrosandboxExecutor（Python 沙箱）", 
                {"name": config.sandbox_name}
            )
            return MicrosandboxExecutor(name=config.sandbox_name)
        except Exception as e:
            log_system_event(
                f"[ExecutorFactory] MicrosandboxExecutor 初始化失败: {e}，回退到 Docker Python 执行器",
                level=logging.WARNING
            )
    
    # 回退到 Docker 执行器（包装为 Python 执行器）
    from sentinel_agent.executor.docker_python_wrapper import DockerPythonExecutor
    return DockerPythonExecutor(get_executor(config))
