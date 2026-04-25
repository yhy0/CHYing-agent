#!/usr/bin/env python3
"""将 Awesome-POC 漏洞文档导入知识库 raw 层（含质量过滤）。

遍历 wiki/Awesome-POC/ 下所有子目录，对每个 .md 文件做质量过滤后
复制到 knowledge/raw/ 对应分区目录。

用法:
    uv run python scripts/import_awesome_poc.py
    uv run python scripts/import_awesome_poc.py --dry-run   # 只统计不复制
"""

import argparse
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
POC_DIR = PROJECT_ROOT / "wiki" / "Awesome-POC"
KB_DIR = PROJECT_ROOT / "knowledge" / "raw"

# Awesome-POC 中文目录名 -> knowledge/raw 分区名
CATEGORY_MAP = {
    "CMS漏洞": "cms",
    "Web应用漏洞": "web",
    "中间件漏洞": "middleware",
    "云安全漏洞": "cloud",
    "人工智能漏洞": "ai",
    "开发框架漏洞": "framework",
    "OA产品漏洞": "oa",
    "数据库漏洞": "database",
    "网络设备漏洞": "network_device",
    "操作系统漏洞": "os",
    "开发语言漏洞": "language",
    "其他漏洞": "other",
}

MIN_CONTENT_LENGTH = 800
MAX_IMG_WITHOUT_CODE = 5


IMG_REF_PATTERN = re.compile(r"!?\[.*?\]\(images/.*?\)")


def _clean_content(content: str) -> str:
    """清理无法被 RAG 使用的内容（图片引用等）。

    - 删除所有 ![alt](images/...) 图片引用（包括行内的）
    - 删除清理后变成空行的行
    """
    cleaned = IMG_REF_PATTERN.sub("", content)
    lines = [line for line in cleaned.splitlines() if line.strip()]
    return "\n".join(lines).strip() + "\n"


def should_skip(content: str) -> str | None:
    """检查文档是否应跳过，返回跳过原因或 None。"""
    if len(content) < MIN_CONTENT_LENGTH:
        return f"内容太短 ({len(content)} < {MIN_CONTENT_LENGTH})"

    has_code_block = "```" in content
    has_url = "http" in content.lower()

    if not has_code_block and not has_url:
        return "无代码块且无 URL"

    img_count = len(re.findall(r"!\[.*?\]\(.*?\)", content))
    if img_count > MAX_IMG_WITHOUT_CODE and not has_code_block:
        return f"纯截图文档 ({img_count} 张图片, 无代码块)"

    return None


def main():
    parser = argparse.ArgumentParser(description="导入 Awesome-POC 到 RAG 知识库")
    parser.add_argument("--dry-run", action="store_true", help="只统计不复制")
    parser.add_argument("--poc-dir", type=Path, default=POC_DIR, help="Awesome-POC 目录")
    parser.add_argument("--kb-dir", type=Path, default=KB_DIR, help="知识库目标目录")
    args = parser.parse_args()

    if not args.poc_dir.exists():
        print(f"[ERROR] Awesome-POC 目录不存在: {args.poc_dir}", file=sys.stderr)
        sys.exit(1)

    stats = {"total": 0, "imported": 0, "skipped": 0}
    partition_counts: dict[str, int] = {}
    skip_reasons: dict[str, int] = {}

    for src_dir in sorted(args.poc_dir.iterdir()):
        if not src_dir.is_dir():
            continue

        partition = CATEGORY_MAP.get(src_dir.name)
        if partition is None:
            continue

        dest_dir = args.kb_dir / partition
        if not args.dry_run:
            dest_dir.mkdir(parents=True, exist_ok=True)

        for md_file in sorted(src_dir.rglob("*.md")):
            stats["total"] += 1

            try:
                content = md_file.read_text(encoding="utf-8").strip()
            except Exception as e:
                print(f"  [SKIP] 读取失败: {md_file.name} ({e})", file=sys.stderr)
                stats["skipped"] += 1
                continue

            reason = should_skip(content)
            if reason:
                stats["skipped"] += 1
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                continue

            stats["imported"] += 1
            partition_counts[partition] = partition_counts.get(partition, 0) + 1

            if not args.dry_run:
                dest_file = dest_dir / md_file.name
                if dest_file.exists():
                    stem = md_file.stem
                    suffix = md_file.suffix
                    dest_file = dest_dir / f"{stem}_{hash(str(md_file)) % 10000}{suffix}"
                cleaned = _clean_content(content)
                dest_file.write_text(cleaned, encoding="utf-8")

    # 输出统计
    print(f"\n{'=' * 50}")
    print(f"Awesome-POC 导入{'(dry-run) ' if args.dry_run else ''}统计")
    print(f"{'=' * 50}")
    print(f"总文件数: {stats['total']}")
    print(f"导入数: {stats['imported']}")
    print(f"跳过数: {stats['skipped']}")
    print(f"\n分区入库数:")
    for p, c in sorted(partition_counts.items()):
        print(f"  {p}: {c}")
    if skip_reasons:
        print(f"\n跳过原因:")
        for reason, count in sorted(skip_reasons.items(), key=lambda x: -x[1]):
            print(f"  {reason}: {count}")


if __name__ == "__main__":
    main()
