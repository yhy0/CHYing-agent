#!/usr/bin/env python3
"""将 GHSA details 数据筛选转换为 markdown 导入知识库 raw 层。

处理 wiki/ghsa-skill-builder/data/ 下的三个汇总文件：
- go_details_all.json
- pip_details_all.json
- maven_details_all.json

筛选有完整漏洞原理分析的条目，转换为 markdown 后按 CWE 类型分区存放。

用法:
    uv run python scripts/import_ghsa.py
    uv run python scripts/import_ghsa.py --dry-run   # 只统计不写入
"""

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GHSA_DATA_DIR = PROJECT_ROOT / "wiki" / "ghsa-skill-builder" / "data"
KB_DIR = PROJECT_ROOT / "knowledge" / "raw" / "ghsa"

DETAIL_FILES = [
    "go_details_all.json",
    "pip_details_all.json",
    "maven_details_all.json",
]

MIN_DESCRIPTION_LENGTH = 300
ALLOWED_SEVERITIES = {"critical", "high"}
TECHNICAL_KEYWORDS = re.compile(
    r"(poc|exploit|payload|proof.of.concept|source.*sink|attack.*path|"
    r"vulnerable.*code|root.cause|bypass|injection|rce|reverse.shell|"
    r"arbitrary.*code|command.*execution|deserialization|traversal)",
    re.IGNORECASE,
)

# CWE 编号到 ghsa 子目录的映射
CWE_DIR_MAP: dict[str, str] = {}
for cwe_id in ("77", "78", "89", "94", "95", "74"):
    CWE_DIR_MAP[cwe_id] = "injection"
for cwe_id in ("22", "23", "73"):
    CWE_DIR_MAP[cwe_id] = "path_traversal"
for cwe_id in ("287", "288", "306", "347"):
    CWE_DIR_MAP[cwe_id] = "auth_bypass"
for cwe_id in ("918",):
    CWE_DIR_MAP[cwe_id] = "ssrf"
for cwe_id in ("502",):
    CWE_DIR_MAP[cwe_id] = "deserialization"
for cwe_id in ("79", "116"):
    CWE_DIR_MAP[cwe_id] = "xss"
for cwe_id in ("611",):
    CWE_DIR_MAP[cwe_id] = "xxe"
for cwe_id in ("295", "327", "328", "330"):
    CWE_DIR_MAP[cwe_id] = "crypto"


def classify_cwe(cwes: list[str]) -> str:
    """根据 CWE 列表确定目标子目录。"""
    for cwe in cwes:
        m = re.search(r"(\d+)", cwe)
        if m and m.group(1) in CWE_DIR_MAP:
            return CWE_DIR_MAP[m.group(1)]
    return "other"


def should_include(record: dict) -> bool:
    """检查记录是否满足入库条件。"""
    severity = (record.get("severity") or "").lower()
    if severity not in ALLOWED_SEVERITIES:
        return False

    description = record.get("description") or ""
    if len(description) < MIN_DESCRIPTION_LENGTH:
        return False

    has_code = "```" in description or "    " in description
    has_keyword = bool(TECHNICAL_KEYWORDS.search(description))
    return has_code or has_keyword


def record_to_markdown(record: dict) -> str:
    """将一条 GHSA 记录转换为 markdown。"""
    summary = record.get("summary", "Unknown Vulnerability")
    ghsa_id = record.get("ghsa_id", "")
    cve_id = record.get("cve_id") or "N/A"
    severity = record.get("severity", "")
    cvss_score = record.get("cvss_score")
    cwes = record.get("cwes") or []
    description = record.get("description") or ""
    vulns = record.get("vulnerabilities") or []

    cvss_str = f"CVSS {cvss_score}" if cvss_score else ""
    cwe_str = ", ".join(cwes) if cwes else "N/A"

    # 包信息
    pkg_lines = []
    for v in vulns:
        pkg = v.get("package", "")
        eco = v.get("ecosystem", "")
        vrange = v.get("vulnerable_range", "")
        pkg_lines.append(f"- **{pkg}** ({eco}): {vrange}")

    parts = [
        f"# {summary}",
        "",
        f"**GHSA**: {ghsa_id} | **CVE**: {cve_id} | **Severity**: {severity} ({cvss_str})",
        "",
        f"**CWE**: {cwe_str}",
    ]

    if pkg_lines:
        parts.append("")
        parts.append("**Affected Packages**:")
        parts.extend(pkg_lines)

    parts.extend([
        "",
        "## Description",
        "",
        description,
    ])

    return "\n".join(parts) + "\n"


def main():
    parser = argparse.ArgumentParser(description="导入 GHSA details 到 RAG 知识库")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写入")
    parser.add_argument("--data-dir", type=Path, default=GHSA_DATA_DIR, help="GHSA 数据目录")
    parser.add_argument("--kb-dir", type=Path, default=KB_DIR, help="知识库 ghsa/ 目标目录")
    args = parser.parse_args()

    stats = {"total": 0, "imported": 0, "skipped": 0}
    dir_counts: dict[str, int] = {}
    eco_counts: dict[str, int] = {}
    seen_ids: set[str] = set()

    for filename in DETAIL_FILES:
        filepath = args.data_dir / filename
        if not filepath.exists():
            print(f"[WARN] 文件不存在，跳过: {filepath}", file=sys.stderr)
            continue

        ecosystem = filename.split("_details_")[0]
        print(f"[INFO] 处理 {filename} ({ecosystem})...", file=sys.stderr)

        try:
            records = json.loads(filepath.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[ERROR] JSON 解析失败: {filepath} ({e})", file=sys.stderr)
            continue

        for record in records:
            stats["total"] += 1
            ghsa_id = record.get("ghsa_id", "")

            if not ghsa_id or ghsa_id in seen_ids:
                stats["skipped"] += 1
                continue
            seen_ids.add(ghsa_id)

            if not should_include(record):
                stats["skipped"] += 1
                continue

            cwes = record.get("cwes") or []
            target_dir_name = classify_cwe(cwes)
            target_dir = args.kb_dir / target_dir_name

            stats["imported"] += 1
            dir_counts[target_dir_name] = dir_counts.get(target_dir_name, 0) + 1
            eco_counts[ecosystem] = eco_counts.get(ecosystem, 0) + 1

            if not args.dry_run:
                target_dir.mkdir(parents=True, exist_ok=True)
                md_content = record_to_markdown(record)
                md_file = target_dir / f"{ghsa_id}.md"
                md_file.write_text(md_content, encoding="utf-8")

    # 输出统计
    print(f"\n{'=' * 50}")
    print(f"GHSA 导入{'(dry-run) ' if args.dry_run else ''}统计")
    print(f"{'=' * 50}")
    print(f"总记录数: {stats['total']}")
    print(f"导入数: {stats['imported']}")
    print(f"跳过数: {stats['skipped']}")
    print(f"\n按生态:")
    for eco, c in sorted(eco_counts.items()):
        print(f"  {eco}: {c}")
    print(f"\n按 CWE 分类:")
    for d, c in sorted(dir_counts.items()):
        print(f"  ghsa/{d}: {c}")


if __name__ == "__main__":
    main()
