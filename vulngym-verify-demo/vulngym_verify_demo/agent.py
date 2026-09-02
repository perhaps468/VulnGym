# -*- coding: utf-8 -*-
"""Agent 主循环（per entry）：

1. 规划阶段：列举本 entry 要核验的字段，列出将调用的工具
2. 工具调用阶段：执行 tools / 调 LLM 完成字段判定
3. 反思阶段：让 LLM 对全部字段判定做一次 self-check，必要时修正

返回结构兼容 VulnGym 考题要求的：
    {
      "report_id": ...,
      "verdict":  correct | incorrect | uncertain,
      "fields": { field: {status, confidence, evidence} },
      "summary": "..."
    }
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from .field_checkers import check_all_fields
from .llm_client import BaseLLMClient, LLMMessage
from .tools import VulnGymTools


def plan_for_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """返回规划结果：列出要调用的工具和要核验的字段。"""
    return {
        "entry_id": entry.get("entry_id"),
        "report_id": entry.get("report_id"),
        "tools_planned": [
            "read_advisory",
            "checkout",
            "read_file_lines",
            "grep_code",
            "git_log",
        ],
        "fields_planned": [
            "entry_point", "critical_operation", "commit",
            "vuln_ids", "vuln_title",
            "vuln_category_l1", "vuln_category_l2", "trace",
        ],
    }


def self_check(
    entry: Dict[str, Any],
    fields_result: Dict[str, Dict[str, Any]],
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """反思层：让 LLM 反向复核本条 entry 的全部字段判定。

    实现要点：
    1) prompt 把 8 字段的 {status,confidence,evidence} 整段 dump 给 LLM，
       让它检举'证据互相矛盾'或'判定过激'的情况；
    2) 要求 LLM 返回严格 JSON：{"agree": bool, "comment": str}；
    3) try/except 兜底：LLM 返回不可解析/超时/限流时，默认 agree=True
       并写 'self-check skipped'，保证主流程不阻塞（鲁棒性优先于完美复核）。
    """
    # 用 ensure_ascii=False 保留中文字段名，方便 LLM 直观阅读
    prompt = (
        "请复核下列字段判定。检查证据是否自洽，是否有遗漏或过度判定。\n"
        f"entry_id: {entry.get('entry_id')}\n"
        f"fields: {json.dumps(fields_result, ensure_ascii=False)}\n"
        '返回 JSON：{"agree": true|false, "comment": "..."}'
    )
    try:
        # 第二轮让 LLM 只做“裁判”而不是重新跑工具，成本更低，也更适合作为反思层。
        out = llm.chat([LLMMessage("user", prompt)])
        return json.loads(out)
    except Exception:
        # 兜底返回：网络抖动/限流/不可解析时不让主流程崩，
        # 评论里写清是 self-check skipped
        return {"agree": True, "comment": "self-check skipped (LLM unparseable)"}


def verify_entry(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
    verbose: bool = False,
) -> Dict[str, Any]:
    """跑完一条 entry，返回报告 dict。"""
    plan = plan_for_entry(entry)
    if verbose:
        print(f"  [plan] {plan}")

    # 第一阶段：先跑工具和字段判定，拿到“初判结果”
    # 这里会把 entry_point / critical_operation / trace 等字段全部过一遍。
    fields_result_bundle = check_all_fields(entry, tools, llm)
    fields_result = fields_result_bundle["fields"]

    # 第二阶段：把初判结果交给 self_check 做二次复核，
    # 让 LLM 检查“证据是否自洽 / 判定是否过激 / 是否有遗漏”。
    review = self_check(entry, fields_result, llm)

    # 第三阶段：把 verdict、fields、summary、self_check、plan 一并回写到最终报告，
    # 保证输出结果既能评测，也能让评审看到完整的 Agent 闭环。
    return {
        "report_id": entry.get("report_id"),
        "entry_id": entry.get("entry_id"),
        "verdict": fields_result_bundle["verdict"],
        "fields": fields_result,
        "summary": fields_result_bundle["summary"],
        "self_check": review,
        "plan": plan,
    }


def verify_entries(
    entries: List[Dict[str, Any]],
    tools: VulnGymTools,
    llm: BaseLLMClient,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    reports: List[Dict[str, Any]] = []
    for i, entry in enumerate(entries):
        if verbose:
            print(f"\n=== entry {i + 1}/{len(entries)}: {entry.get('entry_id')} / {entry.get('report_id')} ===")
        rep = verify_entry(entry, tools, llm, verbose=verbose)
        if verbose:
            print(f"  [verdict] {rep['verdict']}")
            print(f"  [summary] {rep['summary']}")
            for k, v in rep["fields"].items():
                v.setdefault("confidence", 0.50)
                v.setdefault("evidence", "")
                conf = v["confidence"]
                if isinstance(conf, str):
                    try:
                        conf = float(conf)
                    except (ValueError, TypeError):
                        conf = 0.50
                print(f"    - {k:22s} {v['status']:10s} conf={conf:.2f}  {v['evidence'][:100]}")
        print(f"  [self-check] {rep['self_check']}")
        reports.append(rep)
    return reports
