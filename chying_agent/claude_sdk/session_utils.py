"""
Session 路径工具函数

提供 Claude SDK Session JSONL 文件的路径查找和管理功能。
这些工具主要用于 API 层和需要手动查找会话文件的场景。

对于 Agent 执行，推荐直接从 Hook 获取 transcript_path，
而不是使用这些路径查找工具。
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# 模块级 logger
logger = logging.getLogger(__name__)

# 默认项目关键字（用于自动查找项目目录）
DEFAULT_PROJECT_KEYWORD = "CHYing"


def get_claude_projects_dir() -> Path:
    """获取 Claude Code 项目根目录"""
    return Path.home() / ".claude" / "projects"


def get_project_path_for_cwd(cwd: Optional[Path] = None) -> Path:
    """
    根据工作目录获取对应的 Claude 项目路径

    Claude Code 的项目路径格式：将工作目录路径中的 / 替换为 -
    例如：/Users/yhy/Downloads/CHYing-agent -> -Users-yhy-Downloads-CHYing-agent

    Args:
        cwd: 工作目录，默认为当前目录

    Returns:
        Claude 项目路径
    """
    if cwd is None:
        cwd = Path.cwd()

    project_name = str(cwd).replace("/", "-")
    return get_claude_projects_dir() / project_name


def find_project_path(keyword: Optional[str] = None) -> Optional[Path]:
    """
    查找包含指定关键字的 Claude 项目目录

    Args:
        keyword: 项目名关键字，默认使用 DEFAULT_PROJECT_KEYWORD

    Returns:
        找到的项目路径，未找到返回 None
    """
    keyword = keyword or DEFAULT_PROJECT_KEYWORD
    claude_projects = get_claude_projects_dir()
    if not claude_projects.exists():
        return None

    for p in claude_projects.iterdir():
        if p.is_dir() and keyword in p.name:
            return p

    return None


def build_session_jsonl_path(
    session_id: str, project_path: Optional[Path] = None
) -> Optional[Path]:
    """
    构建 session jsonl 文件的完整路径

    Args:
        session_id: 会话 ID
        project_path: 项目路径，如果不提供则自动检测

    Returns:
        jsonl 文件路径，文件不存在返回 None
    """
    if project_path:
        jsonl_file = project_path / f"{session_id}.jsonl"
        if jsonl_file.exists():
            return jsonl_file
        return None

    # 自动检测：先尝试当前工作目录对应的项目
    cwd_project = get_project_path_for_cwd()
    if cwd_project.exists():
        jsonl_file = cwd_project / f"{session_id}.jsonl"
        if jsonl_file.exists():
            return jsonl_file

    # 遍历所有项目目录查找
    claude_projects = get_claude_projects_dir()
    if not claude_projects.exists():
        return None

    for p in claude_projects.iterdir():
        if p.is_dir():
            jsonl_file = p / f"{session_id}.jsonl"
            if jsonl_file.exists():
                return jsonl_file

    return None


def list_sessions_in_project(
    project_path: Optional[Path] = None,
    limit: int = 50,
    include_subagents: bool = False,
) -> List[Dict[str, Any]]:
    """
    列出项目中的所有会话

    Args:
        project_path: 项目路径，如果不提供则自动检测
        limit: 最大返回数量
        include_subagents: 是否包含子代理会话

    Returns:
        会话列表
    """
    sessions = []

    if project_path is None:
        project_path = get_project_path_for_cwd()
        if not project_path.exists():
            project_path = find_project_path()

    if project_path is None or not project_path.exists():
        return sessions

    for jsonl_file in project_path.glob("*.jsonl"):
        # 子代理文件以 agent- 开头
        is_subagent = jsonl_file.name.startswith("agent-")
        if is_subagent and not include_subagents:
            continue

        session_id = jsonl_file.stem
        stat = jsonl_file.stat()

        # 读取时间范围和消息数
        first_timestamp = None
        last_timestamp = None
        message_count = 0
        parent_session_id = None

        try:
            with open(jsonl_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if record.get("type") in ("user", "assistant"):
                            message_count += 1
                            ts = record.get("timestamp")
                            if ts:
                                if first_timestamp is None:
                                    first_timestamp = ts
                                last_timestamp = ts
                        # 获取父会话 ID（子代理文件中的 sessionId 指向主会话）
                        if is_subagent and not parent_session_id:
                            parent_session_id = record.get("sessionId")
                    except json.JSONDecodeError:
                        continue
        except Exception:
            continue

        session_info = {
            "session_id": session_id,
            "file_path": str(jsonl_file),
            "file_size": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "first_timestamp": first_timestamp,
            "last_timestamp": last_timestamp,
            "message_count": message_count,
            "is_subagent": is_subagent,
        }

        if is_subagent and parent_session_id:
            session_info["parent_session_id"] = parent_session_id

        sessions.append(session_info)

    # 按修改时间倒序排序
    sessions.sort(key=lambda x: x.get("modified_at", ""), reverse=True)

    return sessions[:limit]


def find_subagent_files(
    session_id: str, project_path: Optional[Path] = None
) -> List[Path]:
    """
    查找主会话关联的所有子代理文件

    Args:
        session_id: 主会话 ID
        project_path: 项目路径

    Returns:
        子代理 JSONL 文件路径列表
    """
    if project_path is None:
        project_path = get_project_path_for_cwd()
        if not project_path.exists():
            project_path = find_project_path()

    if project_path is None or not project_path.exists():
        return []

    subagent_files = []

    for jsonl_file in project_path.glob("agent-*.jsonl"):
        try:
            with open(jsonl_file, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
                if first_line:
                    record = json.loads(first_line)
                    if record.get("sessionId") == session_id:
                        subagent_files.append(jsonl_file)
        except Exception:
            continue

    return subagent_files


__all__ = [
    "get_claude_projects_dir",
    "get_project_path_for_cwd",
    "find_project_path",
    "build_session_jsonl_path",
    "list_sessions_in_project",
    "find_subagent_files",
    "DEFAULT_PROJECT_KEYWORD",
]
