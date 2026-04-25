"""
路径工具函数
============

提供 Docker 容器路径与宿主机路径之间的转换功能。
容器内模式（CHYING_IN_CONTAINER=1）时，路径转换变为 identity。
"""

import os
from pathlib import Path
from typing import Optional


# Docker 容器中 agent-work 的映射路径
DOCKER_AGENT_WORK_PREFIX = "/root/agent-work"


def is_in_container() -> bool:
    """检查是否在容器内模式运行（CHYING_IN_CONTAINER=1）"""
    return os.getenv("CHYING_IN_CONTAINER") == "1"


def get_project_root() -> Path:
    """
    获取项目根目录

    Returns:
        项目根目录的 Path 对象
    """
    # chying_agent/utils/path_utils.py -> 向上两级是项目根目录
    return Path(__file__).parent.parent.parent


def get_host_agent_work_dir() -> Path:
    """
    获取 agent-work 目录的路径

    容器内模式：返回 /root/agent-work
    宿主机模式：返回 {project_root}/agent-work
    """
    if is_in_container():
        return Path(DOCKER_AGENT_WORK_PREFIX)
    return get_project_root() / "agent-work"


def convert_docker_path_to_host(docker_path: str) -> str:
    """
    将 Docker 容器路径转换为宿主机路径

    容器内模式：直接返回原路径（identity）
    """
    if not docker_path:
        return docker_path

    if is_in_container():
        return docker_path

    if docker_path.startswith(DOCKER_AGENT_WORK_PREFIX):
        host_agent_work = get_host_agent_work_dir()
        relative_path = docker_path[len(DOCKER_AGENT_WORK_PREFIX):].lstrip("/")
        return str(host_agent_work / relative_path)

    return docker_path


def convert_host_path_to_docker(host_path: str) -> str:
    """
    将宿主机路径转换为 Docker 容器路径

    容器内模式：直接返回原路径（identity）
    """
    if not host_path:
        return host_path

    if is_in_container():
        return host_path

    host_agent_work = str(get_host_agent_work_dir())

    if host_path == host_agent_work:
        return DOCKER_AGENT_WORK_PREFIX

    if host_path.startswith(host_agent_work):
        relative_path = host_path[len(host_agent_work):].lstrip("/")
        return f"{DOCKER_AGENT_WORK_PREFIX}/{relative_path}"

    return host_path


def get_work_dir_from_challenge(challenge: dict) -> Optional[str]:
    """
    从 challenge 字典中提取工作目录路径（宿主机路径）

    Args:
        challenge: challenge 信息字典，包含 target_info.path

    Returns:
        宿主机工作目录路径，如果无法获取则返回 None
    """
    if not challenge:
        return None

    target_info = challenge.get("target_info", {})
    challenge_path = target_info.get("path", "")

    if not challenge_path:
        return None

    # 如果是 Docker 路径，转换为宿主机路径
    return convert_docker_path_to_host(challenge_path)
