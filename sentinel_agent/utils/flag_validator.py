"""
FLAG 格式验证工具
==================

用于验证 FLAG 格式是否正确，防止提交不完整的 FLAG。

标准 FLAG 格式：
- 必须以 'flag{' 开头
- 必须以 '}' 结尾
- 中间包含有效内容
"""
import re
from typing import Tuple


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

    # ⭐ 检查是否以 'flag{' 开头（忽略大小写）
    if not flag.lower().startswith("flag{"):
        return False, f"FLAG 必须以 'flag{{' 或 'FLAG{{' 开头（忽略大小写），当前: {flag}..."

    # 检查是否以 '}' 结尾
    if not flag.endswith("}"):
        return False, f"FLAG 必须以 '}}' 结尾，当前: ...{flag[-10:]}"

    # 检查是否包含有效内容
    content = flag[5:-1]  # 去掉 'flag{' 和 '}'
    if not content:
        return False, "FLAG 内容不能为空（flag{} 无效）"

    # 检查是否包含非法字符（可选，根据比赛规则调整）
    # 一般 FLAG 内容只包含字母、数字、下划线、连字符
    if not re.match(r'^[a-zA-Z0-9_\-]+$', content):
        # 警告但不阻止（某些比赛可能允许特殊字符）
        return True, f"⚠️ 警告：FLAG 内容包含特殊字符，请确认是否正确: {content}"

    return True, ""


def extract_flag_from_text(text: str) -> list:
    """
    从文本中提取所有可能的 FLAG

    Args:
        text: 包含 FLAG 的文本

    Returns:
        提取到的 FLAG 列表（去重）
    """
    # 匹配 flag{...} 或 FLAG{...} 格式（忽略大小写）
    pattern = r'[Ff][Ll][Aa][Gg]\{[^}]+\}'
    flags = re.findall(pattern, text)

    # 去重（保持原始大小写）
    unique_flags = []
    seen = set()
    for flag in flags:
        flag_lower = flag.lower()
        if flag_lower not in seen:
            seen.add(flag_lower)
            unique_flags.append(flag)

    return unique_flags


def suggest_flag_fix(incomplete_flag: str) -> str:
    """
    尝试修复不完整的 FLAG

    Args:
        incomplete_flag: 不完整的 FLAG

    Returns:
        修复建议
    """
    suggestions = []

    # ⭐ 忽略大小写检查前缀
    if not incomplete_flag.lower().startswith("flag{"):
        suggestions.append("添加 'flag{' 前缀")

    if not incomplete_flag.endswith("}"):
        suggestions.append("添加 '}' 后缀")

    if suggestions:
        return f"建议修复：{', '.join(suggestions)}"

    return "FLAG 格式看起来正确"


# 示例用法
if __name__ == "__main__":
    test_cases = [
        "flag{hahahahaha_this_is_demo_test_flag}",  # ✓ 正确
        "FLAG{hahahahaha_this_is_demo_test_flag}",  # ✓ 正确（大写）
        "Flag{test_mixed_case}",                     # ✓ 正确（混合大小写）
        "FlaG{another_test}",                        # ✓ 正确（混合大小写）
        "flag{hahahahaha_this_is_demo_test_flag",   # ✗ 缺少 }
        "hahahahaha_this_is_demo_test_flag}",       # ✗ 缺少 flag{
        "flag{}",                                    # ✗ 内容为空
        "flag{test-123_ABC}",                        # ✓ 正确
        "flag{test@#$}",                             # ⚠️ 特殊字符
    ]

    print("=" * 60)
    print("FLAG 格式验证测试")
    print("=" * 60)
    for flag in test_cases:
        is_valid, msg = validate_flag_format(flag)
        status = "✓" if is_valid else "✗"
        print(f"{status} {flag}")
        if msg:
            print(f"  → {msg}")
        if not is_valid:
            print(f"  → {suggest_flag_fix(flag)}")
        print()
