"""
输出处理工具
============

处理工具执行输出的公共函数，包括：
- 长输出保存到文件
- 关键证据提取
"""

import re
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional

from chying_agent.runtime.context import get_current_work_dir


# 关键证据提取的正则模式
EVIDENCE_PATTERNS = [
    # FLAG 模式（各种常见格式）
    (r'flag\{[^}]+\}', 'FLAG'),
    (r'FLAG\{[^}]+\}', 'FLAG'),
    (r'ctf\{[^}]+\}', 'FLAG'),
    (r'CTF\{[^}]+\}', 'FLAG'),
    # 敏感信息
    (r'password[:\s=]+\S+', 'PASSWORD'),
    (r'passwd[:\s=]+\S+', 'PASSWORD'),
    (r'secret[:\s=]+\S+', 'SECRET'),
    (r'api[_-]?key[:\s=]+\S+', 'API_KEY'),
    # 常见漏洞指示
    (r'root:[x*]?:\d+:\d+', 'PASSWD_ENTRY'),
    (r'uid=\d+.*gid=\d+', 'ID_OUTPUT'),
    (r'SQL syntax.*MySQL', 'SQL_ERROR'),
    (r'Warning:.*mysqli', 'SQL_ERROR'),
    (r'<script>.*</script>', 'XSS_PAYLOAD'),
    # CTF 增强模式
    (r'0x[0-9a-fA-F]{8,}', 'HEX_VALUE'),
]


def extract_evidence(output: str, max_matches: int = 10) -> List[Tuple[str, str, str]]:
    """
    从输出中提取关键证据

    Args:
        output: 完整输出内容
        max_matches: 每种类型最多提取的匹配数

    Returns:
        [(类型, 匹配内容, 上下文行), ...]
    """
    evidence = []

    for pattern, evidence_type in EVIDENCE_PATTERNS:
        matches = list(re.finditer(pattern, output, re.IGNORECASE))[:max_matches]
        for match in matches:
            matched_text = match.group(0)
            # 找到匹配所在的行
            pos = match.start()
            line_start = output.rfind('\n', 0, pos) + 1
            line_end = output.find('\n', pos)
            if line_end == -1:
                line_end = len(output)
            context_line = output[line_start:line_end].strip()
            evidence.append((evidence_type, matched_text, context_line))

    return evidence


def save_long_output(
    output: str,
    source_name: str,
    work_dir: Optional[Path] = None
) -> Tuple[str, str]:
    """
    将过长的输出保存到文件，返回精简摘要 + 关键证据

    设计理念：
    - 不把大块 head/tail 塞回上下文（这是导致日志爆炸的根因）
    - 自动提取关键证据（flag、密码、漏洞指示）
    - 不提示"cat 查看完整内容"（避免 LLM 把全量内容读回来）

    Args:
        output: 完整输出内容
        source_name: 来源名称（用于生成文件名，如命令名、脚本名）
        work_dir: 可选，指定保存目录。如果不指定，使用当前题目的工作目录

    Returns:
        (文件路径, 摘要信息)
    """
    # 确定保存目录：优先写入 work_dir/dumps/ 子目录
    if work_dir is None:
        work_dir = get_current_work_dir()

    if work_dir is None:
        project_root = Path(__file__).parent.parent.parent
        work_dir = project_root / "agent-work" / "output"

    dumps_dir = work_dir / "dumps"
    dumps_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name_prefix = source_name.split()[0].replace("/", "_")[:20] if source_name else "output"
    filename = f"{timestamp}_{name_prefix}.txt"
    filepath = dumps_dir / filename

    # 写入文件
    filepath.write_text(output, encoding="utf-8")

    # 提取关键证据
    evidence = extract_evidence(output)

    # 精简摘要：只保留很短的预览（500 字符）
    head_size = 500
    head = output[:head_size].strip()

    # 构建摘要
    summary_parts = [
        f"⚠️ 输出过长（{len(output)} 字符），已保存到文件。",
        f"📁 **文件路径**: {filepath}",
    ]

    # 如果有关键证据，优先展示
    if evidence:
        summary_parts.append("\n🎯 **发现关键证据**:")
        for ev_type, matched, context in evidence[:5]:  # 最多展示 5 条
            summary_parts.append(f"  - [{ev_type}] `{matched}`")
            if context and context != matched:
                summary_parts.append(f"    上下文: {context[:100]}")

    # 简短预览（不再展示 tail）
    summary_parts.append(f"\n📄 **输出预览（前 {head_size} 字符）**:")
    summary_parts.append(head)
    if len(output) > head_size:
        summary_parts.append(f"\n... [省略 {len(output) - head_size} 字符] ...")

    # 提示使用 read_file 和 grep_file 工具
    summary_parts.append(f"\n💡 **查看完整内容**: `read_file(\"{filepath}\")`")
    summary_parts.append(f"💡 **搜索关键词**: `grep_file(\"{filepath}\", \"flag|password|secret\")`")

    summary = "\n".join(summary_parts)
    return str(filepath), summary
