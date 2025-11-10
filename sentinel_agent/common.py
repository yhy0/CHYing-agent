import json
import logging
import sys
import textwrap
import os
from typing import Any, Optional
from datetime import datetime
from pathlib import Path

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

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


# 创建日志目录
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# 生成日志文件名（按日期时间）
log_filename = f"sentinel_agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
log_filepath = LOG_DIR / log_filename

# 配置 logger
logger = logging.getLogger("SentinelAgent")
logger.setLevel(logging.INFO)
logger.handlers.clear()

# 控制台处理器（带颜色）
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredConsoleFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
logger.addHandler(console_handler)

# 文件处理器（纯文本）
file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
file_handler.setFormatter(PlainFileFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
logger.addHandler(file_handler)

logger.propagate = False

# 记录日志文件位置
print(f"📁 日志文件: {log_filepath}")
print(f"📁 日志目录: {LOG_DIR}\n")


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
    """记录日志（控制台带颜色，文件纯文本）"""
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
    logger.log(level, message, extra=extra)


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
