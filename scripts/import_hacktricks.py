#!/usr/bin/env python3
"""将 HackTricks / HackTricks-Cloud 攻击技术文档导入知识库 raw 层。

遍历 wiki/hacktricks/ 和 wiki/hacktricks-cloud/ 目录，
清理 GitBook 格式，按内容领域分区导入 knowledge/raw/。

用法:
    uv run python scripts/import_hacktricks.py
    uv run python scripts/import_hacktricks.py --dry-run
"""

import argparse
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KB_DIR = PROJECT_ROOT / "knowledge" / "raw"

# HackTricks 源目录路径 -> knowledge/raw 分区名
# key 是相对于 wiki/hacktricks/src/ 或 wiki/hacktricks-cloud/src/ 的路径前缀
PARTITION_MAP: list[tuple[str, str, str]] = [
    # (仓库, 源目录前缀, 目标分区)
    # hacktricks-cloud
    ("hacktricks-cloud", "pentesting-cloud/aws-security", "ht_cloud"),
    ("hacktricks-cloud", "pentesting-cloud/azure-security", "ht_cloud"),
    ("hacktricks-cloud", "pentesting-cloud/gcp-security", "ht_cloud"),
    ("hacktricks-cloud", "pentesting-cloud/kubernetes-security", "ht_cloud"),
    ("hacktricks-cloud", "pentesting-cloud/digital-ocean-pentesting", "ht_cloud"),
    ("hacktricks-cloud", "pentesting-cloud/workspace-security", "ht_cloud"),
    ("hacktricks-cloud", "pentesting-ci-cd", "ht_cicd"),
    # hacktricks
    ("hacktricks", "pentesting-web", "ht_web"),
    ("hacktricks", "windows-hardening/active-directory-methodology", "ht_ad"),
    ("hacktricks", "windows-hardening/lateral-movement", "ht_ad"),
    ("hacktricks", "windows-hardening/ntlm", "ht_ad"),
    ("hacktricks", "windows-hardening/stealing-credentials", "ht_ad"),
    ("hacktricks", "windows-hardening/windows-local-privilege-escalation", "ht_windows"),
    ("hacktricks", "linux-hardening/privilege-escalation", "ht_linux"),
    ("hacktricks", "linux-hardening/bypass-bash-restrictions", "ht_linux"),
    ("hacktricks", "linux-hardening/linux-post-exploitation", "ht_linux"),
    ("hacktricks", "network-services-pentesting", "ht_network"),
    ("hacktricks", "binary-exploitation", "ht_binary"),
    ("hacktricks", "generic-methodologies-and-resources", "ht_misc"),
    ("hacktricks", "AI", "ht_misc"),
    ("hacktricks", "crypto", "ht_misc"),
    ("hacktricks", "stego", "ht_misc"),
]

# 跳过的文件名
SKIP_FILES = {"SUMMARY.md", "README.md"}

MIN_CONTENT_LENGTH = 500

# GitBook 格式清理正则
GITBOOK_INCLUDE = re.compile(r"\{\{#include\s+.*?\}\}\s*")
GITBOOK_REF_BLOCK = re.compile(r"\{\{#ref\}\}.*?\{\{#endref\}\}", re.DOTALL)
GITBOOK_HINT = re.compile(r"\{%\s*hint\s+style=\".*?\"\s*%\}(.*?)\{%\s*endhint\s*%\}", re.DOTALL)
GITBOOK_EMBED = re.compile(r"\{%\s*embed\s+url=\"(.*?)\"\s*%\}")
GITBOOK_TABS = re.compile(r"\{%\s*(?:tabs|tab|endtabs|endtab).*?%\}\s*")
IMG_PATTERN = re.compile(r"!?\[.*?\]\(<?\.\./images/.*?>?\)")
FIGURE_TAG = re.compile(r"</?figure>")
EMPTY_LINES = re.compile(r"\n{3,}")


def clean_gitbook(content: str) -> str:
    """清理 GitBook 特有语法，保留纯 markdown 内容。"""
    content = GITBOOK_INCLUDE.sub("", content)
    content = GITBOOK_REF_BLOCK.sub("", content)
    content = GITBOOK_HINT.sub(r"> \1", content)
    content = GITBOOK_EMBED.sub(r"- \1", content)
    content = GITBOOK_TABS.sub("", content)
    content = IMG_PATTERN.sub("", content)
    content = FIGURE_TAG.sub("", content)
    content = EMPTY_LINES.sub("\n\n", content)
    return content.strip()


def main():
    parser = argparse.ArgumentParser(description="导入 HackTricks 到 RAG 知识库")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写入")
    parser.add_argument("--wiki-dir", type=Path, default=PROJECT_ROOT / "wiki", help="wiki 目录")
    parser.add_argument("--kb-dir", type=Path, default=KB_DIR, help="知识库目标目录")
    args = parser.parse_args()

    stats = {"total": 0, "imported": 0, "skipped": 0, "too_short": 0, "skip_file": 0}
    partition_counts: dict[str, int] = {}

    for repo_name, src_prefix, partition in PARTITION_MAP:
        src_dir = args.wiki_dir / repo_name / "src" / src_prefix
        if not src_dir.exists():
            continue

        dest_dir = args.kb_dir / partition
        if not args.dry_run:
            dest_dir.mkdir(parents=True, exist_ok=True)

        for md_file in sorted(src_dir.rglob("*.md")):
            stats["total"] += 1

            if md_file.name in SKIP_FILES:
                stats["skip_file"] += 1
                stats["skipped"] += 1
                continue

            try:
                raw_content = md_file.read_text(encoding="utf-8")
            except Exception as e:
                print(f"  [SKIP] 读取失败: {md_file} ({e})", file=sys.stderr)
                stats["skipped"] += 1
                continue

            cleaned = clean_gitbook(raw_content)

            if len(cleaned) < MIN_CONTENT_LENGTH:
                stats["too_short"] += 1
                stats["skipped"] += 1
                continue

            stats["imported"] += 1
            partition_counts[partition] = partition_counts.get(partition, 0) + 1

            if not args.dry_run:
                safe_name = md_file.stem.replace("/", "_").replace(" ", "-")
                dest_file = dest_dir / f"{safe_name}.md"
                counter = 0
                while dest_file.exists():
                    counter += 1
                    dest_file = dest_dir / f"{safe_name}_{counter}.md"
                dest_file.write_text(cleaned + "\n", encoding="utf-8")

    print(f"\n{'=' * 50}")
    print(f"HackTricks 导入{'(dry-run) ' if args.dry_run else ''}统计")
    print(f"{'=' * 50}")
    print(f"扫描文件数: {stats['total']}")
    print(f"导入数: {stats['imported']}")
    print(f"跳过数: {stats['skipped']} (索引页={stats['skip_file']}, 太短={stats['too_short']})")
    print(f"\n分区入库数:")
    for p, c in sorted(partition_counts.items()):
        print(f"  {p}: {c}")


if __name__ == "__main__":
    main()
