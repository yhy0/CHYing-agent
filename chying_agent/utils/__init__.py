"""
工具模块
========

提供各种辅助工具函数。
"""

from chying_agent.utils.flag_validator import (
    validate_flag_format,
    extract_flag_from_text,
    suggest_flag_fix
)

from chying_agent.utils.recon import (
    auto_recon_web_target,
    format_recon_result_for_llm
)

from chying_agent.utils.path_utils import (
    DOCKER_AGENT_WORK_PREFIX,
    get_project_root,
    get_host_agent_work_dir,
    convert_docker_path_to_host,
    convert_host_path_to_docker,
    get_work_dir_from_challenge,
)

__all__ = [
    # flag_validator
    "validate_flag_format",
    "extract_flag_from_text",
    "suggest_flag_fix",
    # recon
    "auto_recon_web_target",
    "format_recon_result_for_llm",
    # path_utils
    "DOCKER_AGENT_WORK_PREFIX",
    "get_project_root",
    "get_host_agent_work_dir",
    "convert_docker_path_to_host",
    "convert_host_path_to_docker",
    "get_work_dir_from_challenge",
]
