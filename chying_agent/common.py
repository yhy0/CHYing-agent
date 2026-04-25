import json
import logging
import sys
import os
from typing import Any, Optional
from datetime import datetime
from pathlib import Path
from contextvars import ContextVar

LOG_FORMAT = "%(asctime)s [%(levelname)s] | %(message)s" 
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ⭐ 新增：当前题目的上下文变量（用于多线程日志隔离）
# 使用 contextvars 而不是 threading.local，因为支持 asyncio
_current_challenge_code: ContextVar[Optional[str]] = ContextVar('current_challenge_code', default=None)
_challenge_loggers: dict[str, logging.Logger] = {}  # 题目 -> Logger 映射

# ⭐ 新增：当前 Agent 上下文（用于追踪日志来源）
_current_agent_name: ContextVar[str] = ContextVar('current_agent_name', default="")

# 彩色代码
RESET = "\033[0m"
BOLD = "\033[1m"

CATEGORY_STYLES = {
    "LLM": "\033[95m",      # 亮紫色
    "TOOL": "\033[96m",     # 亮青色
    "STATE": "\033[92m",    # 亮绿色
    "SECURITY": "\033[93m", # 亮黄色
    "SYSTEM": "\033[94m",   # 亮蓝色
}

# Agent 名称颜色（醒目区分不同 Agent）
AGENT_STYLES = {
    "executor": "\033[1;36m",           # 粗体青色
    "c2_agent": "\033[1;35m",           # 粗体紫色
    "Brain": "\033[1;33m",              # 粗体黄色
    "Claude SDK": "\033[1;33m",         # 粗体黄色
    "Main Agent": "\033[1;91m",         # 粗体亮红色
    "sub_agent": "\033[1;34m",          # 粗体蓝色
    "Subagent": "\033[1;38;2;255;150;50m",  # 粗体橙色 — 醒目区分子代理
    "Orchestrator": "\033[1;38;2;100;200;255m",  # 粗体天蓝色 — Orchestrator 标签
}

# 子代理工具调用日志样式
SUBAGENT_TOOL_STYLE = "\033[1;38;2;255;150;50m"  # 粗体橙色


def format_tool_source_prefix(is_subagent: bool, subagent_name: str = "") -> str:
    """返回工具调用来源前缀：子代理带橙色 [Subagent:name]，Orchestrator 返回空字符串。"""
    if is_subagent:
        label = f"[Subagent:{subagent_name}] " if subagent_name else "[Subagent] "
        return _apply_style(SUBAGENT_TOOL_STYLE, label)
    return ""


# Orchestrator 标签样式
ORCHESTRATOR_STYLE = AGENT_STYLES.get("Orchestrator", "\033[1;38;2;100;200;255m")


def format_orchestrator_prefix(agent_type: str) -> str:
    """返回 Orchestrator 工具调用来源前缀，带颜色。"""
    return _apply_style(ORCHESTRATOR_STYLE, f"[{agent_type}] ")


# LLM 输出内容高亮（title 关键词 → payload 值颜色）
# 让 agent 的文本响应和思考过程在日志中一眼可辨
_LLM_OUTPUT_STYLES: dict[str, str] = {
    "文本响应": "\033[38;2;220;220;170m",  # 暖米色 — 柔和醒目，不刺眼
    "思考过程": "\033[3;38;5;245m",        # 斜体中灰 — 低调可辨，像旁注
    "Token Usage": "\033[1;38;2;80;220;180m",  # 粗体青绿色 — 醒目但不刺眼
}

LEVEL_STYLES = {
    "DEBUG": "\033[37m",
    "INFO": "\033[38;2;180;250;114m",  # 浅绿色 RGB(180, 250, 114)
    "WARNING": "\033[93m",
    "ERROR": "\033[91m",
    "CRITICAL": "\033[41m",
}


def _supports_color() -> bool:
    """检测当前终端是否支持彩色输出。"""
    return sys.stdout.isatty()


_COLOR_ENABLED = _supports_color()


class ColoredConsoleFormatter(logging.Formatter):
    """带颜色的控制台格式化器"""

    def format(self, record):
        # 保存原始消息
        original_msg = record.getMessage()

        # 先应用 category 彩色（如果终端支持）
        if _COLOR_ENABLED and hasattr(record, 'category'):
            category = record.category.upper()
            style = CATEGORY_STYLES.get(category, "")
            if style:
                # 只给 [CATEGORY] 部分上色
                record.msg = record.msg.replace(f"[{category}]", f"{style}[{category}]{RESET}")

        # 调用父类格式化
        formatted = super().format(record)

        # 应用日志级别颜色（如果终端支持）
        if _COLOR_ENABLED:
            level_name = record.levelname
            level_style = LEVEL_STYLES.get(level_name, "")
            if level_style:
                # 给日志级别部分上色，格式如 "[INFO]"
                formatted = formatted.replace(f"[{level_name}]", f"{level_style}[{level_name}]{RESET}")

        return formatted


class PlainFileFormatter(logging.Formatter):
    """纯文本文件格式化器（不带颜色代码）"""
    
    def format(self, record):
        # 确保文件中不包含任何颜色代码
        formatted = super().format(record)
        # 移除所有 ANSI 颜色代码
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', formatted)


# 全局 logger 实例（单例模式）
_logger_initialized = False
logger = None


def _init_logger():
    """初始化 logger（单例模式，只执行一次）"""
    global _logger_initialized, logger

    if _logger_initialized:
        return logger

    # 创建日志目录
    LOG_DIR = Path(__file__).parent.parent / "logs"
    LOG_DIR.mkdir(exist_ok=True)

    # 生成日志文件名（按日期时间）
    log_filename = f"chying_agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_filepath = LOG_DIR / log_filename

    # 配置 logger
    logger = logging.getLogger("CHYingAgent")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()  # 清除已有的 handler

    # 控制台处理器（带颜色）
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredConsoleFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(console_handler)

    # 文件处理器（纯文本）
    file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
    file_handler.setFormatter(PlainFileFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(file_handler)

    logger.propagate = False

    # 记录日志文件位置（只打印一次）
    print(f"📁 日志文件: {log_filepath}")
    print(f"📁 日志目录: {LOG_DIR}\n")

    _logger_initialized = True
    return logger


# 初始化 logger（模块导入时执行一次）
logger = _init_logger()


# ⭐ 新增：题目日志管理
def set_challenge_context(challenge_code: str, retry_count: int = 0):
    """
    设置当前题目上下文（在解题任务开始时调用）

    Args:
        challenge_code: 题目代码（如 "web001"）
        retry_count: 重试次数（0 = 首次尝试，1 = 第1次重试，...）

    作用：
    - 设置当前线程的题目上下文
    - 创建该题目的独立日志文件（首次）或复用已有文件（重试）
    """
    global _challenge_loggers

    # 设置上下文变量
    _current_challenge_code.set(challenge_code)

    # 如果该题目的 logger 已存在，记录重试分隔符后直接返回
    if challenge_code in _challenge_loggers:
        challenge_logger = _challenge_loggers[challenge_code]
        # ⭐ 添加重试分隔符
        separator = f"\n{'='*80}\n🔄 重试 #{retry_count} 开始（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）\n{'='*80}\n"
        challenge_logger.info(separator)
        return

    # 创建题目日志目录
    LOG_DIR = Path(__file__).parent.parent / "logs"
    CHALLENGE_LOG_DIR = LOG_DIR / "challenges"
    CHALLENGE_LOG_DIR.mkdir(exist_ok=True)

    # 生成题目日志文件名
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    challenge_log_filename = f"{challenge_code}_{timestamp}.log"
    challenge_log_filepath = CHALLENGE_LOG_DIR / challenge_log_filename

    # 创建题目专属 logger
    challenge_logger = logging.getLogger(f"CHYingAgent.{challenge_code}")
    challenge_logger.setLevel(logging.INFO)
    challenge_logger.handlers.clear()

    # 只写入文件，不输出到控制台（避免重复）
    file_handler = logging.FileHandler(challenge_log_filepath, encoding='utf-8')
    file_handler.setFormatter(PlainFileFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    challenge_logger.addHandler(file_handler)

    challenge_logger.propagate = False

    # 保存到全局字典
    _challenge_loggers[challenge_code] = challenge_logger

    # 记录题目日志文件位置
    logger.info(f"📝 题目日志: {challenge_log_filepath}")

    # ⭐ 添加首次尝试的标记
    if retry_count == 0:
        header = f"\n{'='*80}\n🎯 题目: {challenge_code} - 首次尝试（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）\n{'='*80}\n"
    else:
        header = f"\n{'='*80}\n🔄 重试 #{retry_count} 开始（{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}）\n{'='*80}\n"
    challenge_logger.info(header)


def clear_challenge_context():
    """清除当前题目上下文（在解题任务结束时调用），并关闭对应的 FileHandler"""
    challenge_code = _current_challenge_code.get()
    _current_challenge_code.set(None)

    # 清理该题目的 logger 和 FileHandler，避免资源泄漏
    if challenge_code and challenge_code in _challenge_loggers:
        challenge_logger = _challenge_loggers.pop(challenge_code)
        for handler in challenge_logger.handlers[:]:
            handler.close()
            challenge_logger.removeHandler(handler)


def set_agent_context(agent_name: str):
    """设置当前 Agent 上下文（在 Agent 执行时调用）"""
    _current_agent_name.set(agent_name)


def clear_agent_context():
    """清除当前 Agent 上下文"""
    _current_agent_name.set("")


def get_current_agent_name() -> str:
    """获取当前 Agent 名称"""
    return _current_agent_name.get()


def get_current_challenge_logger() -> Optional[logging.Logger]:
    """获取当前题目的 logger（如果存在）"""
    challenge_code = _current_challenge_code.get()
    if challenge_code:
        return _challenge_loggers.get(challenge_code)
    return None


def _apply_style(style: str, text: str) -> str:
    """应用颜色样式"""
    if not _COLOR_ENABLED or not style:
        return text
    return f"{style}{text}{RESET}"


def _format_payload(payload: Any) -> Optional[str]:
    """
    格式化 payload 为 key=value 格式（不截断，保留完整内容）
    """
    if payload is None:
        return None

    if isinstance(payload, dict):
        # 优先显示的关键字段
        priority_keys = ['exit_code', 'exit', 'status', 'error', 'command', 'result']

        parts = []
        shown_keys = set()

        # 先显示优先字段
        for key in priority_keys:
            if key in payload:
                val = _format_value(payload[key])
                parts.append(f"{key}={val}")
                shown_keys.add(key)

        # 显示所有其他字段（不限制数量）
        for key, value in payload.items():
            if key in shown_keys:
                continue
            val = _format_value(value)
            parts.append(f"{key}={val}")

        return " ".join(parts) if parts else None

    if isinstance(payload, list):
        # 完整输出 list
        try:
            return json.dumps(payload, ensure_ascii=False)
        except Exception:
            return str(payload)

    return _format_value(payload)


def _format_value(value: Any) -> str:
    """格式化单个值（不截断，保留完整内容用于日志分析）"""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        # 完整输出 dict 内容
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    if isinstance(value, list):
        # 完整输出 list 内容
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    # 字符串处理
    s = str(value)
    # 移除换行符（保持单行日志格式）
    s = s.replace('\n', ' ').replace('\r', '')
    # 如果包含空格，加引号
    if ' ' in s or not s:
        s = f'"{s}"'
    return s


def _log_with_category(category: str, title: str, payload: Any, *, level: int) -> None:
    """
    记录日志（控制台带颜色，文件纯文本）

    格式：[CATEGORY] [AgentName] Component.动作 | key=value key=value

    ⭐ 双日志系统：
    - 全局日志：所有题目的日志混合（用于查看整体进度）
    - 题目日志：当前题目的独立日志（用于深入分析）
    """
    category_key = category.upper()
    style = CATEGORY_STYLES.get(category_key, "")

    # 获取当前 Agent 名称
    agent_name = get_current_agent_name()

    # 构建消息
    # 格式：[CATEGORY] [AgentName] title | payload
    label = _apply_style(style, f"[{category_key}]")
    if agent_name:
        # 获取 Agent 专属颜色
        agent_style = AGENT_STYLES.get(agent_name, "\033[1;37m")  # 默认粗体白色
        agent_label = _apply_style(agent_style, f"[{agent_name}]")
    else:
        agent_label = ""

    formatted_payload = _format_payload(payload)
    if formatted_payload:
        # 对 LLM 输出内容（文本响应、思考过程）的 payload 值着色
        colored_payload = formatted_payload
        if _COLOR_ENABLED:
            for keyword, llm_style in _LLM_OUTPUT_STYLES.items():
                if keyword in title:
                    colored_payload = f"{llm_style}{formatted_payload}{RESET}"
                    break
        if agent_label:
            message = f"{label} {agent_label} {title} | {colored_payload}"
        else:
            message = f"{label} {title} | {colored_payload}"
    else:
        if agent_label:
            message = f"{label} {agent_label} {title}"
        else:
            message = f"{label} {title}"

    # 确保 level 是整数
    if not isinstance(level, int):
        raise TypeError(f"level must be an integer, got {type(level)} with value {level}")

    # 添加 category 属性用于格式化器识别
    extra = {'category': category_key}

    # 1. 写入全局日志（始终写入）
    logger.log(level, message, extra=extra)

    # 2. 写入题目日志（如果存在）
    challenge_logger = get_current_challenge_logger()
    if challenge_logger:
        challenge_logger.log(level, message, extra=extra)


def log_agent_thought(title: str, payload: Any = None) -> None:
    """记录LLM的思考与输出。"""
    _log_with_category("LLM", title, payload, level=logging.INFO)


def log_tool_event(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录工具调用及其结果。"""
    _log_with_category("TOOL", title, payload, level=level)


def log_security_event(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录安全审查相关的消息。"""
    _log_with_category("SECURITY", title, payload, level=level)


def log_system_event(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录系统级别的提示，如初始化等。"""
    _log_with_category("SYSTEM", title, payload, level=level)


# Skill 调用专用样式
_SKILL_STYLE = "\033[1;38;2;180;130;255m"  # 粗体淡紫色 — 与 TOOL 青色和 SYSTEM 蓝色区分

# 知识库检索专用样式
_KB_STYLE = "\033[1;38;2;0;230;180m"  # 粗体青绿色


def log_skill_event(skill_name: str, args: str = "") -> None:
    """格式化记录 Skill 工具调用，使用专属紫色高亮。"""
    category_key = "SYSTEM"
    style = CATEGORY_STYLES.get(category_key, "")
    label = _apply_style(style, f"[{category_key}]")

    agent_name = get_current_agent_name()
    if agent_name:
        agent_style = AGENT_STYLES.get(agent_name, "\033[1;37m")
        agent_label = _apply_style(agent_style, f"[{agent_name}]")
    else:
        agent_label = ""

    skill_text = _apply_style(_SKILL_STYLE, f"Skill 调用: {skill_name}")
    if args:
        args_text = _apply_style(_SKILL_STYLE, f"args={args}")
        title = f"{skill_text} | {args_text}"
    else:
        title = skill_text

    header = f"{label} {agent_label} {title}".strip() if agent_label else f"{label} {title}"

    extra = {"category": category_key}
    logger.log(logging.INFO, header, extra=extra)

    challenge_logger = get_current_challenge_logger()
    if challenge_logger:
        challenge_logger.log(logging.INFO, header, extra=extra)


def log_kb_event(message: str, doc_count: int = 0, source: str = "") -> None:
    """格式化记录知识库检索事件，使用青绿色高亮。"""
    category_key = "SYSTEM"
    style = CATEGORY_STYLES.get(category_key, "")
    label = _apply_style(style, f"[{category_key}]")

    agent_name = get_current_agent_name()
    if agent_name:
        agent_style = AGENT_STYLES.get(agent_name, "\033[1;37m")
        agent_label = _apply_style(agent_style, f"[{agent_name}]")
    else:
        agent_label = ""

    kb_prefix = _apply_style(_KB_STYLE, "[KB]")
    kb_text = _apply_style(_KB_STYLE, message)
    if doc_count:
        count_text = _apply_style(_KB_STYLE, f"({doc_count} 篇)")
        title = f"{kb_prefix} {kb_text} {count_text}"
    else:
        title = f"{kb_prefix} {kb_text}"
    if source:
        source_text = _apply_style(_KB_STYLE, f"[{source}]")
        title = f"{source_text} {title}"

    header = f"{label} {agent_label} {title}".strip() if agent_label else f"{label} {title}"

    extra = {"category": category_key}
    logger.log(logging.INFO, header, extra=extra)

    challenge_logger = get_current_challenge_logger()
    if challenge_logger:
        challenge_logger.log(logging.INFO, header, extra=extra)


# Guidance Loop 分段指导专用样式
_GUIDANCE_STYLE = "\033[1;38;2;255;200;50m"  # 粗体金黄色

_GUIDANCE_TYPE_LABELS = {
    "continue": "继续执行",
    "pivot": "换方向 - ABANDON",
    "blocked": "绕过阻塞",
    "exhausted": "会话耗尽",
}


def log_guidance_event(
    round_count: int,
    max_rounds: int,
    guidance_type: str,
    guidance_len: int = 0,
) -> None:
    """格式化记录 Guidance Loop 分段指导事件，使用金黄色高亮。

    Args:
        round_count: 当前轮数
        max_rounds: 最大轮数
        guidance_type: 分支类型 (continue/pivot/blocked/exhausted)
        guidance_len: guidance 消息长度
    """
    category_key = "SYSTEM"
    style = CATEGORY_STYLES.get(category_key, "")
    label = _apply_style(style, f"[{category_key}]")

    agent_name = get_current_agent_name()
    if agent_name:
        agent_style = AGENT_STYLES.get(agent_name, "\033[1;37m")
        agent_label = _apply_style(agent_style, f"[{agent_name}]")
    else:
        agent_label = ""

    tag = _apply_style(_GUIDANCE_STYLE, "[GUIDANCE]")
    type_label = _GUIDANCE_TYPE_LABELS.get(guidance_type, guidance_type)

    if guidance_type == "exhausted":
        detail = _apply_style(_GUIDANCE_STYLE, f"{round_count} 轮指导后仍无突破，标记会话耗尽")
        title = f"{tag} {detail}"
    else:
        round_text = _apply_style(_GUIDANCE_STYLE, f"分段指导 {round_count}/{max_rounds}")
        type_text = _apply_style(_GUIDANCE_STYLE, f"({type_label})")
        len_text = f" | guidance_len={guidance_len}" if guidance_len else ""
        title = f"{tag} {round_text} {type_text}{len_text}"

    header = f"{label} {agent_label} {title}".strip() if agent_label else f"{label} {title}"

    extra = {"category": category_key}
    level = logging.WARNING if guidance_type == "exhausted" else logging.INFO
    logger.log(level, header, extra=extra)

    challenge_logger = get_current_challenge_logger()
    if challenge_logger:
        challenge_logger.log(level, header, extra=extra)


# Task 下发专用样式
_TASK_DISPATCH_STYLE = "\033[1;38;2;100;180;255m"  # 粗体亮蓝色 — 与 Tool 青色区分
_TASK_TYPE_STYLES = {
    "local_bash": "\033[38;2;130;200;160m",   # 柔绿色
    "agent": "\033[38;2;200;160;255m",         # 柔紫色
}


def log_task_event(data: dict, agent_type: str = "Orchestrator") -> None:
    """格式化记录 Task 下发事件，以醒目格式展示任务分配信息。

    展示效果类似 TodoWrite 的高亮 checklist，让 task_started 在日志中一眼可辨。
    """
    description = data.get("description", "unknown task")
    task_id = data.get("task_id", "")
    task_type = data.get("task_type", "")

    category_key = "SYSTEM"
    style = CATEGORY_STYLES.get(category_key, "")
    label = _apply_style(style, f"[{category_key}]")

    agent_name = get_current_agent_name()
    if agent_name:
        agent_style = AGENT_STYLES.get(agent_name, "\033[1;37m")
        agent_label = _apply_style(agent_style, f"[{agent_name}]")
    else:
        agent_label = ""

    # 标题行：>> Task 下发: description
    title = _apply_style(_TASK_DISPATCH_STYLE, f">> Task 下发: {description}")

    # 详情行
    type_style = _TASK_TYPE_STYLES.get(task_type, "\033[37m")
    detail_parts = []
    if task_type:
        detail_parts.append(f"  type  = {_apply_style(type_style, task_type)}")
    if task_id:
        detail_parts.append(f"  id    = {task_id}")
    detail_lines = "\n".join(detail_parts) if detail_parts else ""

    header = f"{label} {agent_label} {title}".strip() if agent_label else f"{label} {title}"
    message = f"{header}\n{detail_lines}" if detail_lines else header

    extra = {"category": category_key}
    logger.log(logging.INFO, message, extra=extra)

    challenge_logger = get_current_challenge_logger()
    if challenge_logger:
        challenge_logger.log(logging.INFO, message, extra=extra)


# TodoWrite 专用样式
_TODO_STYLE = "\033[1;38;2;255;165;0m"  # 粗体橙色 — 醒目且与其他类别区分
_TODO_STATUS_STYLES = {
    "in_progress": "\033[1;33m",  # 粗体黄色 ▶
    "pending": "\033[37m",        # 白色 ○
    "completed": "\033[32m",      # 绿色 ✔
}
_TODO_STATUS_ICONS = {
    "in_progress": "▶",
    "pending": "○",
    "completed": "✔",
}


def _format_todo_list(todos: list[dict]) -> str:
    """将 TodoWrite 的 todos 格式化为可读的 checklist。"""
    lines = []
    for todo in todos:
        content = todo.get("content", "")
        status = todo.get("status", "pending")
        icon = _TODO_STATUS_ICONS.get(status, "?")
        style = _TODO_STATUS_STYLES.get(status, "")
        if _COLOR_ENABLED and style:
            lines.append(f"  {style}{icon} {content}{RESET}")
        else:
            lines.append(f"  {icon} {content}")
    return "\n".join(lines)


def log_todo_event(todos: list[dict]) -> None:
    """格式化记录 TodoWrite 调用，以高亮 checklist 形式展示。"""
    checklist = _format_todo_list(todos)

    category_key = "TOOL"
    style = CATEGORY_STYLES.get(category_key, "")
    label = _apply_style(style, f"[{category_key}]")

    agent_name = get_current_agent_name()
    if agent_name:
        agent_style = AGENT_STYLES.get(agent_name, "\033[1;37m")
        agent_label = _apply_style(agent_style, f"[{agent_name}]")
    else:
        agent_label = ""

    title = _apply_style(_TODO_STYLE, "📋 TodoWrite 攻击计划")

    total = len(todos)
    done = sum(1 for t in todos if t.get("status") == "completed")
    progress = _apply_style(_TODO_STYLE, f"({done}/{total})")

    header = f"{label} {agent_label} {title} {progress}".strip() if agent_label else f"{label} {title} {progress}"
    message = f"{header}\n{checklist}"

    extra = {"category": category_key}
    logger.log(logging.INFO, message, extra=extra)

    challenge_logger = get_current_challenge_logger()
    if challenge_logger:
        challenge_logger.log(logging.INFO, message, extra=extra)
