"""\
Knowledge Base — 预编译技术知识库
==================================

基于 Karpathy "LLM Knowledge Bases" 模式，用结构化的 markdown wiki
替代 embedding + BM25 检索。

组件:
- CompiledKB: markdown wiki 加载器 + frontmatter 关键词匹配
- KB Client: challenge_solver / prompt_compiler 调用的查询接口
"""

from .client import query_kb, check_kb_health

# 兼容旧接口名称
query_rag = query_kb

__all__ = ["query_kb", "query_rag", "check_kb_health"]
