"""
CompiledKB — 极简的 markdown wiki 加载器 + frontmatter 关键词匹配。

Karpathy: "index.md works surprisingly well at moderate scale
(~100 sources, ~hundreds of pages) and avoids the need for
embedding-based RAG infrastructure."

用法:
    kb = CompiledKB("/path/to/compiled_kb")
    matches = kb.match("buffer overflow NX enabled ret2libc", category="pwn")
    for page_id, score in matches:
        print(kb.get_content(page_id))
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class PageMeta:
    """一个 wiki 页面的 frontmatter 元数据。"""
    category: str = ""
    tags: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    related: list[str] = field(default_factory=list)


def _parse_frontmatter(file_path: Path) -> tuple[dict, str]:
    """解析 markdown 文件的 YAML frontmatter 和正文。

    Returns:
        (frontmatter_dict, body_text)
    """
    text = file_path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}, text

    # 找第二个 ---
    end = text.find("---", 3)
    if end == -1:
        return {}, text

    fm_text = text[3:end].strip()
    body = text[end + 3:].strip()

    try:
        fm = yaml.safe_load(fm_text) or {}
    except yaml.YAMLError:
        logger.warning("[CompiledKB] YAML frontmatter 解析失败: %s", file_path)
        fm = {}

    return fm, body


class CompiledKB:
    """加载 compiled_kb/techniques/ 下的 markdown 页面，
    通过 frontmatter 的 tags + triggers 做关键词匹配。"""

    def __init__(self, kb_dir: str):
        self.kb_dir = Path(kb_dir)
        self.pages: dict[str, PageMeta] = {}    # page_id -> metadata
        self.contents: dict[str, str] = {}       # page_id -> full markdown (含 frontmatter)
        self._slug_to_page_id: dict[str, str] = {}  # slug -> page_id (反向索引)
        self._load()

    def _load(self) -> None:
        """扫描 techniques/**/*.md，解析 YAML frontmatter，构建索引。"""
        techniques_dir = self.kb_dir / "techniques"
        if not techniques_dir.exists():
            logger.warning("[CompiledKB] techniques 目录不存在: %s", techniques_dir)
            return

        count = 0
        for md_file in sorted(techniques_dir.rglob("*.md")):
            try:
                page_id = md_file.relative_to(techniques_dir).with_suffix("").as_posix()
                fm, body = _parse_frontmatter(md_file)

                self.pages[page_id] = PageMeta(
                    category=str(fm.get("category", "")).lower(),
                    tags=[str(t).lower() for t in fm.get("tags", [])],
                    triggers=[str(t).lower() for t in fm.get("triggers", [])],
                    related=[str(r) for r in fm.get("related", [])],
                )
                # 存完整正文（不含 frontmatter 的 YAML 部分）
                self.contents[page_id] = body
                count += 1
            except Exception as e:
                logger.warning("[CompiledKB] 加载失败 %s: %s", md_file, e)

        logger.info("[CompiledKB] 已加载 %d 个技术页面", count)

        # 构建 slug → page_id 反向索引（用于 get_related 解析短名称）
        # 冲突时从 map 中移除该 slug，强制调用方使用完整 category/slug 路径
        _ambiguous: set[str] = set()
        for page_id in self.pages:
            slug = page_id.rsplit("/", 1)[-1]  # "web/sqli" → "sqli"
            if slug in _ambiguous:
                pass  # 已知冲突，跳过
            elif slug in self._slug_to_page_id:
                logger.warning(
                    "[CompiledKB] slug 冲突，related 必须写完整路径: '%s' "
                    "(冲突页面: %s vs %s)",
                    slug, self._slug_to_page_id[slug], page_id,
                )
                del self._slug_to_page_id[slug]
                _ambiguous.add(slug)
            else:
                self._slug_to_page_id[slug] = page_id

    def _score_pages(
        self,
        query_lower: str,
        pages: dict[str, PageMeta],
        *,
        category: str = "",
        category_boost: bool = False,
    ) -> list[tuple[str, float]]:
        """对给定页面集合做 frontmatter 关键词打分。"""
        scores: dict[str, float] = {}

        for page_id, meta in pages.items():
            score = 0.0

            # tag 匹配（精确词出现在 query 中）
            for tag in meta.tags:
                if tag and tag in query_lower:
                    score += 10.0

            # trigger 匹配（短语子串匹配）
            for trigger in meta.triggers:
                if trigger and trigger in query_lower:
                    score += 5.0

            # category 匹配 — 仅作 boost，不独立产生 hit
            if score > 0 and category_boost and category and meta.category == category:
                score += 3.0

            if score > 0:
                scores[page_id] = score

        return sorted(scores.items(), key=lambda x: -x[1])

    def match(
        self,
        query: str,
        category: str = "",
        top_k: int = 5,
    ) -> list[tuple[str, float]]:
        """frontmatter 关键词匹配。

        匹配顺序：
            1. 若指定 category，先对同类别页面做硬过滤匹配
            2. 同类别无命中时，再回退到全库匹配

        评分规则:
            tag 命中:       +10
            trigger 命中:   +5
            category 匹配:  +3 (仅在全库回退阶段生效)

        Returns:
            [(page_id, score)] 按分数降序，最多 top_k 个。
        """
        if not self.pages:
            return []

        query_lower = query.lower()
        cat_lower = category.lower().strip() if category else ""

        if cat_lower:
            same_category_pages = {
                page_id: meta
                for page_id, meta in self.pages.items()
                if meta.category == cat_lower
            }
            if same_category_pages:
                ranked = self._score_pages(query_lower, same_category_pages, category=cat_lower)
                if ranked:
                    return ranked[:top_k]

        ranked = self._score_pages(
            query_lower,
            self.pages,
            category=cat_lower,
            category_boost=bool(cat_lower),
        )
        return ranked[:top_k]

    def get_content(self, page_id: str) -> Optional[str]:
        """获取页面的完整 markdown 正文。"""
        return self.contents.get(page_id)

    def get_meta(self, page_id: str) -> Optional[PageMeta]:
        """获取页面的 frontmatter 元数据。"""
        return self.pages.get(page_id)

    def get_related(self, page_id: str) -> list[str]:
        """获取相关页面 ID 列表（只返回实际存在的页面）。
        支持 related 字段中的完整 page_id（如 'web/sqli'）和 slug（如 'sqli'）。
        slug 有歧义（跨分类重名）时，该条目被跳过并记录 warning，
        请在 frontmatter 中改用完整路径（如 'web/jwt'）。
        """
        meta = self.pages.get(page_id)
        if not meta:
            return []
        result = []
        for r in meta.related:
            if r in self.pages:
                # 完整 page_id 直接匹配
                result.append(r)
            elif r in self._slug_to_page_id:
                # slug 通过反向索引解析（已在加载时排除冲突 slug）
                result.append(self._slug_to_page_id[r])
            else:
                logger.warning(
                    "[CompiledKB] get_related: '%s' 无法解析（页面不存在或 slug 有歧义），"
                    "请在 %s 的 related 中改用完整路径",
                    r, page_id,
                )
        return result

    @property
    def page_count(self) -> int:
        return len(self.pages)


# ---------- 经验记录 ----------

def record_experience(
    kb_dir: str,
    technique_id: str,
    challenge_name: str,
    solved: bool,
    notes: str = "",
) -> Path:
    """写一条解题经验到 experience/ 目录。

    经验记录是原始素材（Karpathy 的 raw sources），
    后续通过 ingest 操作编译进 techniques/ 的 wiki 页面。

    Returns:
        写入的文件路径。
    """
    exp_dir = Path(kb_dir) / "experience"
    exp_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    slug = technique_id.replace("/", "_")
    path = exp_dir / f"{timestamp}_{slug}.md"

    result_emoji = "✅ 成功" if solved else "❌ 失败"

    # 用 yaml.dump 序列化 frontmatter，避免 challenge_name 含冒号/引号/换行时
    # 手拼 YAML 产生的 ScannerError（e.g. 'Test: colon' 会破坏 YAML 结构）
    frontmatter = yaml.dump(
        {
            "technique": technique_id,
            "challenge": challenge_name,
            "solved": solved,
            "date": timestamp[:10],
        },
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    ).strip()

    content = f"""---
{frontmatter}
---

# {challenge_name}

匹配技术: [[{technique_id}]]
结果: {result_emoji}

## 笔记
{notes}
"""
    path.write_text(content.strip() + "\n", encoding="utf-8")

    # 追加 log.md（在 kb_dir 的上级目录，即 knowledge/）
    log_path = Path(kb_dir).parent / "log.md"
    if log_path.exists():
        result_tag = "solve_ok" if solved else "solve_fail"
        log_entry = f"\n- [{timestamp[:10]}] {result_tag} | {challenge_name} → {technique_id}\n"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(log_entry)

    logger.info("[CompiledKB] 记录经验: %s -> %s", technique_id, path.name)
    return path
