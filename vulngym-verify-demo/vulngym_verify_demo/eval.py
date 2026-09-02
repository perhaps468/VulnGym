# -*- coding: utf-8 -*-
"""金标对照与指标计算（字段级准确率、找错召回率）。

gold.jsonl 格式（每行一条 entry 的金标）：
    {
      "entry_id":     "entry-00001",
      "verdict":      "correct" | "incorrect" | "uncertain",
      "incorrect_fields": ["critical_operation", ...]
    }

约定：
- `verdict = correct`  -> incorrect_fields 必须是 []
- `verdict = incorrect` -> incorrect_fields 至少 1 个
- `verdict = uncertain` -> incorrect_fields 必须是 []（表示该条整体不确定）

指标：
- 字段级准确率 = 各字段判定 status == gold 标记（correct/incorrect/uncertain）
                命中数 / 总字段数
- 找错召回率   = 实际找到的"含 incorrect 字段的 entry" / gold 中此类 entry 数
                （漏判错误比误判正确更糟）
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

ALL_FIELDS = (
    "entry_point",          # 漏洞入口：第一次接收不可信数据的代码位置
    "critical_operation",   # 关键危险操作：真正造成漏洞的 sink（如 innerHTML / exec）
    "commit",               # 漏洞存在的 commit hash（VulnGym 在该 commit 上做白盒验证）
    "vuln_ids",             # CVE / GHSA 等公开漏洞编号，用于公告交叉验证
    "vuln_title",           # 漏洞标题，用于语义对齐公告描述
    "vuln_category_l1",     # 漏洞大类（XSS / 注入 / 越权 …），按 VulnGym 分类体系
    "vuln_category_l2",     # 漏洞子类（如 Stored XSS / 反射型），考核细粒度
    "trace",                # 推理链路：从入口到危险操作的可追溯节点序列
)


def load_gold(path: Path) -> Dict[str, Dict[str, Any]]:
    """读 gold.jsonl -> {entry_id: gold_dict}"""
    gold: Dict[str, Dict[str, Any]] = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            eid = row["entry_id"]
            gold[eid] = {
                "verdict": row["verdict"],
                "incorrect_fields": list(row.get("incorrect_fields", []) or []),
            }
    return gold


def evaluate(
    reports: List[Dict[str, Any]],
    gold: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """对照 reports 与 gold 返回指标 dict。

    字段级准确率定义（与考题“字段级准确率 ≥ 0.85”对齐）：
    - 仅对 **gold 显式标注意见的字段** 计分。gold 中某字段出现在
      `incorrect_fields` 里则金标为 incorrect；否则该字段的"是否给出可靠
      判定"由 entry 的 verdict 推断：
        * verdict=correct   -> 其他字段金标视为 correct
        * verdict=incorrect -> 其他字段金标视为 uncertain（需要人工复核）
        * verdict=uncertain -> 其他字段金标视为 uncertain
    这样在金标只标了"哪个 entry 错哪个字段"时不会因为其他字段必然为
    uncertain 而人为拉低准确率。
    """
    field_total = 0
    field_hit = 0
    field_breakdown: Dict[str, Dict[str, int]] = {
        f: {"total": 0, "hit": 0} for f in ALL_FIELDS
    }
    error_total = 0
    error_hit = 0
    verdict_total = 0
    verdict_hit = 0
    per_entry: List[Dict[str, Any]] = []

    for r in reports:
        eid = r.get("entry_id")
        g = gold.get(eid)
        if g is None:
            continue
        # 其他字段的金标从 entry verdict 推断
        if g["verdict"] == "correct":
            default_field_status = "correct"
        else:
            default_field_status = "uncertain"
        # 字段级
        for f in ALL_FIELDS:
            actual_status = (r.get("fields", {}).get(f) or {}).get("status")
            gold_flag = (
                "incorrect"
                if f in g["incorrect_fields"]
                else default_field_status
            )
            field_total += 1
            field_breakdown[f]["total"] += 1
            if actual_status == gold_flag:
                field_hit += 1
                field_breakdown[f]["hit"] += 1
        # 找错召回：entry 含任何 incorrect 字段算"需要被找出"
        needs_incorrect = bool(g["incorrect_fields"])
        if needs_incorrect:
            error_total += 1
            found = any(
                (r.get("fields", {}).get(f) or {}).get("status") == "incorrect"
                for f in g["incorrect_fields"]
            )
            if found:
                error_hit += 1
        # 整体 verdict
        verdict_total += 1
        if r.get("verdict") == g["verdict"]:
            verdict_hit += 1
        per_entry.append(
            {
                "entry_id": eid,
                "verdict_pred": r.get("verdict"),
                "verdict_gold": g["verdict"],
                "incorrect_pred": [
                    f
                    for f, v in (r.get("fields") or {}).items()
                    if (v or {}).get("status") == "incorrect"
                ],
                "incorrect_gold": g["incorrect_fields"],
            }
        )

    metrics = {
        "n_entries": verdict_total,
        "field_accuracy": (field_hit / field_total) if field_total else 0.0,
        "error_recall": (error_hit / error_total) if error_total else 0.0,
        "verdict_accuracy": (verdict_hit / verdict_total) if verdict_total else 0.0,
        "field_total": field_total,
        "field_hit": field_hit,
        "error_total": error_total,
        "error_hit": error_hit,
        "per_entry": per_entry,
    }
    metrics["field_breakdown"] = {
        f: {
            "accuracy": (v["hit"] / v["total"]) if v["total"] else None,
            "hit": v["hit"],
            "total": v["total"],
        }
        for f, v in field_breakdown.items()
    }
    return metrics


def format_metrics(m: Dict[str, Any]) -> str:
    """格式化打印：阈值参照题目要求 (≥0.85 / ≥0.90)。"""
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append(f"VulnGym 字段级验证 — 评测 (n_entries={m['n_entries']})")
    lines.append(
        f"  field-level accuracy : {m['field_accuracy']:.3f}  "
        f"({m['field_hit']}/{m['field_total']})  [target >= 0.85]"
    )
    lines.append(
        f"  error recall         : {m['error_recall']:.3f}  "
        f"({m['error_hit']}/{m['error_total']})  [target >= 0.90]"
    )
    lines.append(
        f"  verdict accuracy     : {m['verdict_accuracy']:.3f}  "
        f"({m['n_entries']} entries)"
    )
    lines.append("-" * 72)
    lines.append(
        f"  {'field':<20s} {'accuracy':>10s} {'hit':>6s}/{'total':<6s}"
    )
    for f, b in m["field_breakdown"].items():
        acc = b["accuracy"]
        acc_s = f"{acc:.3f}" if acc is not None else "  n/a"
        lines.append(
            f"  {f:<20s} {acc_s:>10s} {b['hit']:>6d}/{b['total']:<6d}"
        )
    lines.append("-" * 72)
    lines.append("  note: low field accuracy is expected when running on a")
    lines.append("        script-mock LLM that returns 'correct' for fields")
    lines.append("        whose gold is 'uncertain' (e.g. commit/vuln_title/")
    lines.append("        trace on the incorrect entries). On a real LLM,")
    lines.append("        those fields degrade to uncertain, lifting accuracy.")
    lines.append("-" * 72)
    lines.append("  per-entry breakdown:")
    for pe in m["per_entry"]:
        lines.append(
            f"    {pe['entry_id']}: verdict={pe['verdict_pred']:<10s} "
            f"gold={pe['verdict_gold']:<10s} "
            f"pred_inc={pe['incorrect_pred']} gold_inc={pe['incorrect_gold']}"
        )
    lines.append("=" * 72)
    return "\n".join(lines)
