"""
Skills 按需加载器
================

职责：
- 根据漏洞类型按需加载对应的 SKILL.md
- 为 Advisor Agent 提供漏洞知识库
- 支持关键词匹配自动识别漏洞类型

作者：CHYing
日期：2025-12-10
"""

import os
import re
import logging
from typing import Optional, List, Dict
from pathlib import Path

from chying_agent.common import log_system_event


# Skills 目录路径
SKILLS_DIR = Path(__file__).parent


# 漏洞类型关键词映射
SKILL_KEYWORDS = {
    "sqli": [
        "sql", "injection", "database", "query", "select", "union",
        "mysql", "postgresql", "sqlite", "oracle", "mssql",
        "login", "bypass", "authentication", "' or", "1=1",
        "数据库", "注入", "查询", "登录绕过"
    ],
    "xss": [
        "xss", "cross-site", "script", "alert", "document.cookie",
        "javascript", "html", "dom", "reflected", "stored",
        "sanitize", "escape", "encode", "input", "output",
        "跨站", "脚本", "反射", "存储"
    ],
    "rce": [
        "rce", "command", "execution", "shell", "system",
        "exec", "eval", "os.system", "subprocess", "popen",
        "ping", "cmd", "run", "反弹", "webshell",
        "命令执行", "代码执行", "远程执行"
    ],
    "file-inclusion": [
        "lfi", "rfi", "include", "file", "path", "traversal",
        "directory", "../", "..\\", "etc/passwd", "php://",
        "wrapper", "filter", "input", "data://",
        "文件包含", "目录遍历", "路径穿越"
    ],
    "ssrf": [
        "ssrf", "server-side", "request", "forgery", "url",
        "fetch", "curl", "http://", "https://", "localhost",
        "127.0.0.1", "internal", "metadata", "169.254",
        "服务端请求伪造", "内网", "代理"
    ],
    "auth-bypass": [
        "auth", "bypass", "authentication", "authorization",
        "login", "password", "credential", "session", "cookie",
        "jwt", "token", "admin", "privilege", "escalation",
        "认证绕过", "权限", "越权", "idor", "bac"
    ],
    "web-recon": [
        "recon", "reconnaissance", "scan", "enumerate", "discover",
        "directory", "subdomain", "port", "service", "version",
        "fingerprint", "technology", "cms", "framework",
        "信息收集", "扫描", "枚举", "指纹"
    ]
}


def get_available_skills() -> List[str]:
    """
    获取所有可用的 Skills 列表

    Returns:
        Skills 名称列表
    """
    skills = []
    for item in SKILLS_DIR.iterdir():
        if item.is_dir() and (item / "SKILL.md").exists():
            skills.append(item.name)
    return skills


def load_skill(skill_name: str) -> Optional[str]:
    """
    加载指定的 Skill 内容

    Args:
        skill_name: Skill 名称（如 "sqli", "xss", "rce"）

    Returns:
        Skill 内容（Markdown 格式），如果不存在返回 None
    """
    skill_path = SKILLS_DIR / skill_name / "SKILL.md"

    if not skill_path.exists():
        log_system_event(
            f"[Skills] Skill 不存在: {skill_name}",
            {"path": str(skill_path)},
            level=logging.WARNING
        )
        return None

    try:
        content = skill_path.read_text(encoding="utf-8")

        # 移除 YAML front matter（如果存在）
        if content.startswith("---"):
            # 找到第二个 ---
            end_idx = content.find("---", 3)
            if end_idx != -1:
                content = content[end_idx + 3:].strip()

        log_system_event(
            f"[Skills] 加载 Skill: {skill_name}",
            {"length": len(content)}
        )

        return content

    except Exception as e:
        log_system_event(
            f"[Skills] 加载 Skill 失败: {skill_name}",
            {"error": str(e)},
            level=logging.ERROR
        )
        return None


def detect_skill_from_hint(hint: str) -> List[str]:
    """
    根据题目提示自动检测可能的漏洞类型

    Args:
        hint: 题目提示内容

    Returns:
        匹配的 Skill 名称列表（按匹配度排序）
    """
    if not hint:
        return []

    hint_lower = hint.lower()
    matches = {}

    for skill_name, keywords in SKILL_KEYWORDS.items():
        score = 0
        for keyword in keywords:
            if keyword.lower() in hint_lower:
                # 完整匹配得分更高
                if re.search(rf'\b{re.escape(keyword)}\b', hint_lower, re.IGNORECASE):
                    score += 2
                else:
                    score += 1

        if score > 0:
            matches[skill_name] = score

    # 按匹配度排序
    sorted_matches = sorted(matches.items(), key=lambda x: x[1], reverse=True)

    if sorted_matches:
        log_system_event(
            f"[Skills] 从提示中检测到漏洞类型",
            {"hint_preview": hint[:100], "matches": dict(sorted_matches)}
        )

    return [skill for skill, _ in sorted_matches]


def detect_skill_from_response(response: str) -> List[str]:
    """
    根据响应内容检测可能的漏洞类型

    Args:
        response: HTTP 响应或工具输出

    Returns:
        匹配的 Skill 名称列表
    """
    if not response:
        return []

    response_lower = response.lower()
    detected = []

    # SQL 错误特征
    sql_errors = [
        "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
        "syntax error", "query failed", "database error",
        "you have an error in your sql"
    ]
    if any(err in response_lower for err in sql_errors):
        detected.append("sqli")

    # 模板注入特征（SSTI）
    # 检测 7*7=49 的计算结果，但需要更严格的匹配避免误报
    ssti_patterns = [
        r'\b49\b',  # 49 作为独立数字（不是 149、490 等）
    ]
    ssti_indicators = ['{{', '{%', '${', 'jinja', 'twig', 'freemarker', 'velocity']

    # 如果响应中有模板语法特征，或者有独立的 49
    has_ssti_indicator = any(ind in response_lower for ind in ssti_indicators)
    has_49_standalone = re.search(r'\b49\b', response) is not None

    if has_ssti_indicator or (has_49_standalone and "{{7*7}}" not in response):
        detected.append("rce")

    # 文件包含特征
    if "root:" in response or "/etc/passwd" in response:
        detected.append("file-inclusion")

    # 命令执行特征
    if "uid=" in response or "gid=" in response:
        detected.append("rce")

    return detected


def load_skills_for_context(
    hint: Optional[str] = None,
    response: Optional[str] = None,
    explicit_skills: Optional[List[str]] = None,
    max_skills: int = 2
) -> str:
    """
    根据上下文加载相关的 Skills

    Args:
        hint: 题目提示
        response: 响应内容
        explicit_skills: 显式指定的 Skills
        max_skills: 最多加载的 Skill 数量

    Returns:
        合并后的 Skills 内容
    """
    skills_to_load = set()

    # 1. 显式指定的 Skills
    if explicit_skills:
        skills_to_load.update(explicit_skills)

    # 2. 从提示中检测
    if hint:
        detected = detect_skill_from_hint(hint)
        skills_to_load.update(detected[:max_skills])

    # 3. 从响应中检测
    if response:
        detected = detect_skill_from_response(response)
        skills_to_load.update(detected[:max_skills])

    # 限制数量
    skills_to_load = list(skills_to_load)[:max_skills]

    if not skills_to_load:
        log_system_event("[Skills] 未检测到相关漏洞类型，不加载 Skills")
        return ""

    # 加载 Skills
    loaded_contents = []
    for skill_name in skills_to_load:
        content = load_skill(skill_name)
        if content:
            loaded_contents.append(f"## {skill_name.upper()} 漏洞知识库\n\n{content}")

    if loaded_contents:
        result = "\n\n---\n\n".join(loaded_contents)
        log_system_event(
            f"[Skills] 加载了 {len(loaded_contents)} 个 Skills",
            {"skills": skills_to_load}
        )
        return result

    return ""


def get_skill_summary() -> str:
    """
    获取所有 Skills 的摘要（用于 Advisor 快速参考）

    Returns:
        Skills 摘要表格
    """
    available = get_available_skills()

    summary_lines = [
        "## 可用漏洞知识库",
        "",
        "| Skill | 关键词 |",
        "|-------|--------|"
    ]

    for skill in available:
        keywords = SKILL_KEYWORDS.get(skill, [])[:5]
        summary_lines.append(f"| {skill} | {', '.join(keywords)} |")

    return "\n".join(summary_lines)
