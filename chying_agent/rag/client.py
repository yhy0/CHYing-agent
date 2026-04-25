"""\
Knowledge Base Client
=====================

基于 Karpathy "LLM Knowledge Bases" 模式，用预编译的 markdown wiki
替代 embedding + BM25 检索。

供 challenge_solver / prompt_compiler / mcp_tools 调用。
知识库不存在时静默返回空结果，不影响正常解题流程。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------- 单例加载 ----------

_kb = None  # type: ignore
_kb_loaded = False


def _get_kb():
    """延迟加载 CompiledKB 单例。"""
    global _kb, _kb_loaded
    if _kb_loaded:
        return _kb

    _kb_loaded = True
    # knowledge/ 目录在项目根目录，和 chying_agent/ 同级
    project_root = Path(__file__).parent.parent.parent
    kb_dir = project_root / "knowledge" / "wiki"
    if not kb_dir.exists():
        logger.info("[KB] knowledge/wiki/ 目录不存在，知识库未启用")
        return None

    try:
        from .compiled_kb import CompiledKB
        _kb = CompiledKB(str(kb_dir))
        logger.info("[KB] 知识库已加载: %d 个技术页面", _kb.page_count)
    except Exception as e:
        logger.warning("[KB] 知识库加载失败: %s", e)
        _kb = None

    return _kb


# ---------- 查询接口 ----------

async def check_kb_health() -> dict | None:
    """检查知识库健康状态。

    Returns:
        健康信息 dict，未加载时返回 None
    """
    kb = _get_kb()
    if kb is None:
        return None
    return {
        "status": "ok",
        "type": "compiled_kb",
        "page_count": kb.page_count,
    }


async def query_kb(
    name: str = "",
    category: str = "",
    hint: str = "",
    description: str = "",
    top_k: int = 10,
) -> list[dict]:
    """查询知识库，返回匹配的技术页面列表。

    知识库不存在时返回空列表，不抛异常。

    Args:
        name: 题目名称
        category: 题目类别
        hint: 题目 hint
        description: 题目描述
        top_k: 返回候选数量

    Returns:
        匹配结果列表 [{id, source_id, section, partition, score, snippet}]
    """
    kb = _get_kb()
    if kb is None:
        return []

    query = " ".join(filter(None, [name, category, hint, description]))
    if not query.strip():
        return []

    matches = kb.match(query, category=category, top_k=top_k)
    if not matches:
        return []

    logger.info(
        "[KB] 匹配到 %d 个技术页面 (top: %s, score=%.0f)",
        len(matches),
        matches[0][0],
        matches[0][1],
    )

    results = []
    for page_id, score in matches:
        content = kb.get_content(page_id)
        if content:
            results.append({
                "id": page_id,
                "source_id": page_id,
                "section": "",
                "partition": page_id.split("/")[0] if "/" in page_id else "",
                "score": score,
                "snippet": content,
            })

    return results


# ---------- 格式化 ----------

def _extract_doc_summary(content: str, max_chars: int = 2000) -> str:
    """从 markdown 文档中提取摘要：标题层级 + 每节首段。"""
    if len(content) <= max_chars:
        return content

    lines = content.split("\n")
    summary_parts: list[str] = []
    in_code_block = False
    section_lines = 0
    max_section_lines = 3
    total_chars = 0

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue

        if stripped.startswith("#"):
            summary_parts.append(line)
            total_chars += len(line) + 1
            section_lines = 0
            continue

        if not stripped:
            continue

        if section_lines < max_section_lines:
            summary_parts.append(line)
            total_chars += len(line) + 1
            section_lines += 1

        if total_chars >= max_chars:
            break

    return "\n".join(summary_parts)


def format_kb_results_for_prompt(candidates: list[dict]) -> Optional[str]:
    """将知识库结果格式化为注入 prompt 的完整文本。"""
    if not candidates:
        return None

    parts = [
        "## 📖 技术知识库匹配结果\n",
        "以下是与本题目匹配的攻击技术知识。",
        "请仔细阅读并据此制定攻击策略。\n",
    ]

    for i, doc in enumerate(candidates, 1):
        score = doc.get("score", 0)
        source_id = doc.get("source_id", doc.get("id", "unknown"))
        snippet = doc.get("snippet", "")

        parts.append(f"### [{i}] {source_id} (匹配度: {score:.0f})\n")
        parts.append(snippet)
        parts.append("\n---\n")

    return "\n".join(parts)


def format_kb_results_for_compiler(candidates: list[dict]) -> Optional[str]:
    """将知识库结果格式化为 PromptCompiler 专用的精简文本。"""
    if not candidates:
        return None

    parts = [
        "## 技术知识库匹配结果（摘要）\n",
    ]

    for i, doc in enumerate(candidates, 1):
        score = doc.get("score", 0)
        source_id = doc.get("source_id", doc.get("id", "unknown"))
        snippet = doc.get("snippet", "")

        summary = _extract_doc_summary(snippet, max_chars=500)
        parts.append(f"### [{i}] {source_id} (匹配度: {score:.0f})")
        parts.append(summary)
        parts.append("")

    return "\n".join(parts)
