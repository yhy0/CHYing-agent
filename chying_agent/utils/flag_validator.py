"""
FLAG 格式验证工具
==================

用于验证 FLAG 格式是否正确，防止提交不完整的 FLAG。

支持的 FLAG 格式前缀（不区分大小写）：
- flag{...} / FLAG{...}
- ctf{...} / CTF{...}
- aliyunctf{...}
- alictf{...}
"""
import re
from typing import Tuple, List, Optional

# ==================== 支持的 FLAG 格式前缀 ====================
# 不区分大小写
SUPPORTED_FLAG_PREFIXES = [
    "flag",
    "ctf",
    "aliyunctf",
    "alictf",
]


def get_flag_pattern() -> str:
    """
    生成匹配所有支持格式的正则表达式

    Returns:
        正则表达式字符串
    """
    # 构建 (flag|ctf|aliyunctf|...) 的模式
    prefixes_pattern = "|".join(SUPPORTED_FLAG_PREFIXES)
    # 不区分大小写匹配：prefix{内容}
    return rf'(?i)({prefixes_pattern})\{{[^}}]+\}}'


def validate_flag_format(flag: str) -> Tuple[bool, str]:
    """
    验证 FLAG 格式是否正确

    Args:
        flag: 待验证的 FLAG 字符串

    Returns:
        (is_valid, error_message) 元组
        - is_valid: 是否有效
        - error_message: 错误信息（如果无效）
    """
    if not flag:
        return False, "FLAG 不能为空"

    flag_lower = flag.lower()

    # 检查是否以支持的前缀开头
    matched_prefix = None
    for prefix in SUPPORTED_FLAG_PREFIXES:
        if flag_lower.startswith(f"{prefix}{{"):
            matched_prefix = prefix
            break

    if not matched_prefix:
        supported_examples = ", ".join(f"{p}{{...}}" for p in SUPPORTED_FLAG_PREFIXES)
        return False, f"FLAG 格式不正确，支持的格式如：{supported_examples} 等"

    # 检查是否以 '}' 结尾
    if not flag.endswith("}"):
        return False, f"FLAG 必须以 '}}' 结尾，当前: ...{flag[-10:]}"

    # 检查是否包含有效内容
    prefix_len = len(matched_prefix) + 1  # prefix + '{'
    content = flag[prefix_len:-1]  # 去掉前缀和 '}'
    if not content:
        return False, f"FLAG 内容不能为空（{matched_prefix}{{}} 无效）"

    # 检查是否包含非法字符（可选，根据比赛规则调整）
    # 一般 FLAG 内容只包含字母、数字、下划线、连字符
    if not re.match(r'^[a-zA-Z0-9_\-]+$', content):
        # 警告但不阻止（某些比赛可能允许特殊字符）
        return True, f"⚠️ 警告：FLAG 内容包含特殊字符，请确认是否正确: {content}"

    return True, ""


def extract_flag_from_text(text: str) -> List[str]:
    """
    从文本中提取所有可能的 FLAG

    Args:
        text: 包含 FLAG 的文本

    Returns:
        提取到的 FLAG 列表（去重）
    """
    # 使用完整匹配提取所有 FLAG
    full_flags = []
    for match in re.finditer(get_flag_pattern(), text):
        full_flags.append(match.group(0))

    # 去重（保持原始大小写）
    unique_flags = []
    seen = set()
    for flag in full_flags:
        flag_lower = flag.lower()
        if flag_lower not in seen:
            seen.add(flag_lower)
            unique_flags.append(flag)

    return unique_flags


def get_flag_prefix(flag: str) -> Optional[str]:
    """
    获取 FLAG 的前缀类型

    Args:
        flag: FLAG 字符串

    Returns:
        前缀类型（如 "flag", "aliyunctf"），未匹配返回 None
    """
    flag_lower = flag.lower()
    for prefix in SUPPORTED_FLAG_PREFIXES:
        if flag_lower.startswith(f"{prefix}{{"):
            return prefix
    return None


def suggest_flag_fix(incomplete_flag: str) -> str:
    """
    尝试修复不完整的 FLAG

    Args:
        incomplete_flag: 不完整的 FLAG

    Returns:
        修复建议
    """
    suggestions = []

    # 检查是否有任何支持的前缀
    has_prefix = any(
        incomplete_flag.lower().startswith(f"{p}{{")
        for p in SUPPORTED_FLAG_PREFIXES
    )

    if not has_prefix:
        suggestions.append("添加正确的前缀（如 flag{, ctf{, aliyunctf{ 等）")

    if not incomplete_flag.endswith("}"):
        suggestions.append("添加 '}' 后缀")

    if suggestions:
        return f"建议修复：{', '.join(suggestions)}"

    return "FLAG 格式看起来正确"


def get_supported_formats_hint() -> str:
    """
    获取支持的 FLAG 格式提示（用于系统提示词）

    Returns:
        格式化的提示字符串
    """
    examples = [f"{p}{{...}}" for p in SUPPORTED_FLAG_PREFIXES]
    return f"支持的 FLAG 格式：{', '.join(examples)} 等"
