# -*- coding: utf-8 -*-
"""CLI 入口：JSONL -> JSONL 报告 + 终端摘要。

用法：
    python -m vulngym_verify_demo.cli \
        --entries mock_data/entries.jsonl \
        --repo-cache mock_repo \
        --advisories mock_advisories \
        --out out/reports.jsonl \
        --llm auto \
        --verbose
"""
from __future__ import annotations

import argparse
import io
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, List

from .agent import verify_entries
from .eval import evaluate, format_metrics, load_gold
from .llm_client import make_client
from .tools import VulnGymTools


# Windows console 默认 cp936，强制 UTF-8 输出，避免中文乱码。
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


def iter_jsonl(path: Path) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def print_summary(reports: List[dict]) -> None:
    c = Counter(r["verdict"] for r in reports)
    print()
    print("=" * 72)
    print(f"VulnGym 字段级验证 — 总览 (n={len(reports)})")
    print(f"  correct   : {c.get('correct', 0)}")
    print(f"  incorrect : {c.get('incorrect', 0)}")
    print(f"  uncertain : {c.get('uncertain', 0)}")
    print("-" * 72)
    print(f"{'entry_id':<12} {'report_id':<24} {'verdict':<10} summary")
    print("-" * 72)
    for r in reports:
        print(
            f"{r['entry_id']:<12} {r['report_id']:<24} "
            f"{r['verdict']:<10} {r['summary']}"
        )
    print("=" * 72)


def main(argv: List[str] | None = None) -> int:
    # CLI 统一收口所有外部输入：
    # 1) 数据输入（entries / gold）
    # 2) 本地资源输入（repo-cache / advisories）
    # 3) 运行模式输入（llm / verbose / bench）
    p = argparse.ArgumentParser(description="VulnGym 字段级验证 Demo")
    p.add_argument("--entries", required=True, help="entries.jsonl 路径")
    p.add_argument("--repo-cache", required=True, help="本地仓库缓存根目录")
    p.add_argument("--advisories", required=True, help="本地公告缓存目录")
    p.add_argument("--out", default="out/reports.jsonl", help="输出报告 JSONL")
    p.add_argument("--llm", default="auto", choices=["auto", "qwen", "glm", "deepseek", "mock"],
                   help="LLM 后端：auto 模式按 .env 顺序(qwen→glm→deepseek)自动选真实后端，全部失败则用 mock")
    p.add_argument("--verbose", action="store_true",
                   help="打印每条 entry 的规划/字段判定/自检细节，便于截图复盘")
    p.add_argument(
        "--gold",
        default=None,
        help="gold.jsonl 路径；提供后会在 Summary 之后追加字段级准确率与找错召回率",
    )
    p.add_argument(
        "--bench",
        action="store_true",
        help="快捷评测模式：等价于 --gold mock_data/gold.jsonl，便于直接跑准确率/召回率",
    )
    args = p.parse_args(argv)

    # bench 只是 gold 的语法糖，避免演示时手敲完整路径。
    if args.bench and not args.gold:
        args.gold = "mock_data/gold.jsonl"

    entries_path = Path(args.entries)
    repo_cache = Path(args.repo_cache)
    advisory_dir = Path(args.advisories)
    out_path = Path(args.out)

    if not entries_path.exists():
        print(f"[ERROR] entries file not found: {entries_path}", file=sys.stderr)
        return 2

    entries = list(iter_jsonl(entries_path))
    print(f"[load] {len(entries)} entries from {entries_path}")

    tools = VulnGymTools(repo_cache_dir=repo_cache, advisory_dir=advisory_dir)
    llm = make_client(args.llm)
    print(f"[llm] using {type(llm).__name__}")

    reports = verify_entries(entries, tools, llm, verbose=args.verbose)
    write_jsonl(out_path, reports)
    print(f"[save] wrote {len(reports)} reports to {out_path}")

    print_summary(reports)

    if args.gold:
        gold_path = Path(args.gold)
        if not gold_path.exists():
            print(f"[ERROR] gold file not found: {gold_path}", file=sys.stderr)
            return 3
        gold = load_gold(gold_path)
        metrics = evaluate(reports, gold)
        print()
        print(format_metrics(metrics))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
