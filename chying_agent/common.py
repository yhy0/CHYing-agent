import json
import logging
import sys
import textwrap
import os
from typing import Any, Optional
from datetime import datetime
from pathlib import Path
from contextvars import ContextVar

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ⭐ 新增：当前题目的上下文变量（用于多线程日志隔离）
# 使用 contextvars 而不是 threading.local，因为支持 asyncio
_current_challenge_code: ContextVar[Optional[str]] = ContextVar('current_challenge_code', default=None)
_challenge_loggers: dict[str, logging.Logger] = {}  # 题目 -> Logger 映射

# 彩色代码
RESET = "\033[0m"
CATEGORY_STYLES = {
    "LLM": "\033[95m",
    "TOOL": "\033[96m",
    "STATE": "\033[92m",
    "SECURITY": "\033[93m",
    "SYSTEM": "\033[94m",
}
LEVEL_STYLES = {
    "DEBUG": "\033[37m",
    "INFO": "\033[97m",
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
        
        # 应用彩色（如果终端支持）
        if _COLOR_ENABLED and hasattr(record, 'category'):
            category = record.category.upper()
            style = CATEGORY_STYLES.get(category, "")
            if style:
                # 只给 [CATEGORY] 部分上色
                record.msg = record.msg.replace(f"[{category}]", f"{style}[{category}]{RESET}")
        
        return super().format(record)


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
    """清除当前题目上下文（在解题任务结束时调用）"""
    _current_challenge_code.set(None)


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
    if payload is None:
        return None
    if isinstance(payload, (dict, list)):
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        text = str(payload)
    return textwrap.indent(text, "  ")


def _log_with_category(category: str, title: str, payload: Any, *, level: int) -> None:
    """
    记录日志（控制台带颜色，文件纯文本）

    ⭐ 双日志系统：
    - 全局日志：所有题目的日志混合（用于查看整体进度）
    - 题目日志：当前题目的独立日志（用于深入分析）
    """
    category_key = category.upper()
    style = CATEGORY_STYLES.get(category_key, "")

    # 构建消息（带颜色标记）
    label = _apply_style(style, f"[{category_key}]")
    message_lines = [f"{label} {title}"]
    formatted_payload = _format_payload(payload)
    if formatted_payload:
        message_lines.append(formatted_payload)
    message = "\n".join(message_lines)

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


def log_state_update(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录状态更新或关键结论。"""
    _log_with_category("STATE", title, payload, level=level)


def log_security_event(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录安全审查相关的消息。"""
    _log_with_category("SECURITY", title, payload, level=level)


def log_system_event(title: str, payload: Any = None, *, level: int = logging.INFO) -> None:
    """记录系统级别的提示，如初始化等。"""
    _log_with_category("SYSTEM", title, payload, level=level)
