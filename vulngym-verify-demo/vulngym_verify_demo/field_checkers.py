# -*- coding: utf-8 -*-
"""字段级三态判定：entry_point / critical_operation / vuln_ids / commit /
vuln_title / vuln_category_l1 / vuln_category_l2 / trace。

每个 check_field_X 返回：
    {
      "status":     "correct" | "incorrect" | "uncertain",
      "confidence": float in [0, 1],
      "evidence":   一句话以上，引用工具返回的具体内容
    }

策略：
- 优先用工具做确定性检查（grep_code / read_file_lines）
- 信息不足或需要语义理解时调用 LLM（带 mock fallback）
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .llm_client import BaseLLMClient, LLMMessage
from .tools import ToolResult, VulnGymTools, normalize_project_from_repo


# ---------- 辅助：line 归一化 ----------
def _line_range(value: Any) -> Tuple[int, int]:
    """把 int 或 "a-b" 转成 (start, end)。"""
    if isinstance(value, int):
        return (value, value)
    if isinstance(value, str) and "-" in value:
        a, b = value.split("-", 1)
        return (int(a), int(b))
    raise ValueError(f"bad line spec: {value!r}")


def _norm_code(code: str) -> str:
    # 归一化工具 1/2：把连续空白(空格/制表/换行)折叠成单空格
    # 目的：实测代码和标注代码常常只是缩进/换行不同，归一化后方便做包含判定
    return re.sub(r"\s+", " ", (code or "").strip())


# ============================================================
# 单字段判定
# ============================================================
def check_entry_point(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    # entry_point 是高优先级字段，判定顺序分三层：
    # 1) 精确校验：checkout 到目标 commit，直接读取标注 line 对应代码；
    # 2) 容错校验：若当前行不匹配，再检查邻近 ±5 行是否只是行号漂移；
    # 3) 最终兜底：仍不匹配则判 incorrect，并把 actual/expected 写进 evidence。
    ep = entry["entry_point"]
    project = normalize_project_from_repo(entry["repo_url"])
    commit = entry["commit"]
    co = tools.checkout(project, commit)
    if not co.ok:
        return {"status": "incorrect", "confidence": 0.95,
                "evidence": f"无法 checkout 到 commit={commit[:7]}：{co.error}"}

    reads = tools.read_file_lines(co.data["cwd"], ep["file"],
                                  *_line_range(ep["line"]))
    if not reads.ok:
        # 文件根本不存在 -> 明确 incorrect（典型数据脏）
        return {"status": "incorrect", "confidence": 0.95,
                "evidence": f"文件不存在：{ep['file']}（{reads.error}）"}

    snippet = reads.data["snippet"]
    actual = _norm_code(snippet)
    expected = _norm_code(ep["code"])
    # 允许“标注代码是实测代码的子串”或反过来，兼容多行截取差异。
    if expected in actual or actual in expected:
        return {"status": "correct", "confidence": 0.90,
                "evidence": f"checkout 后 {ep['file']}:{ep['line']} 代码片段匹配 (snippet={snippet.strip()[:120]})"}

    # 第二层：行号可能因为 commit 漂移或标注误差发生偏移，尝试局部窗口复核。
    s, e = _line_range(ep["line"])
    near_start, near_end = max(1, s - 5), e + 5
    near = tools.read_file_lines(co.data["cwd"], ep["file"], near_start, near_end)
    if near.ok and expected in _norm_code(near.data["snippet"]):
        return {"status": "uncertain", "confidence": 0.55,
                "evidence": f"行号偏移：在 {near_start}-{near_end} 范围内找到匹配代码片段，但原 line {ep['line']} 不匹配"}

    return {"status": "incorrect", "confidence": 0.85,
            "evidence": f"代码片段不匹配：actual={actual[:80]} expected={expected[:80]}"}


def check_critical_operation(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    co_field = entry["critical_operation"]
    project = normalize_project_from_repo(entry["repo_url"])
    commit = entry["commit"]
    co = tools.checkout(project, commit)
    if not co.ok:
        return {"status": "incorrect", "confidence": 0.95,
                "evidence": f"无法 checkout：{co.error}"}

    reads = tools.read_file_lines(co.data["cwd"], co_field["file"],
                                  *_line_range(co_field["line"]))
    if not reads.ok:
        return {"status": "incorrect", "confidence": 0.95,
                "evidence": f"critical_operation 文件不存在：{co_field['file']}"}

    actual = _norm_code(reads.data["snippet"])
    expected = _norm_code(co_field["code"])
    if expected in actual or actual in expected:
        return {"status": "correct", "confidence": 0.90,
                "evidence": f"checkout 后 {co_field['file']}:{co_field['line']} 匹配 (snippet={reads.data['snippet'].strip()[:120]})"}

    # 临近窗口搜索
    s, e = _line_range(co_field["line"])
    near = tools.read_file_lines(co.data["cwd"], co_field["file"], max(1, s - 5), e + 5)
    if near.ok and expected in _norm_code(near.data["snippet"]):
        return {"status": "uncertain", "confidence": 0.55,
                "evidence": f"行号漂移：邻近 ±5 行内能匹配，但 line {co_field['line']} 不匹配"}

    # 用 grep 兜底
    grep = tools.grep_code(co.data["cwd"], co_field["file"], re.escape(co_field["code"].strip()))
    if grep.ok and grep.data["hits"]:
        first = grep.data["hits"][0]
        return {"status": "incorrect", "confidence": 0.85,
                "evidence": f"行号错误：实际匹配行 {first['line']}，标注 {co_field['line']}（{first['text'][:80]}）"}

    return {"status": "incorrect", "confidence": 0.85,
            "evidence": f"代码片段不匹配：actual={actual[:80]} expected={expected[:80]}"}


def check_commit(entry: Dict[str, Any], tools: VulnGymTools) -> Dict[str, Any]:
    commit = entry.get("commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        return {"status": "incorrect", "confidence": 0.99,
                "evidence": f"commit 不是 40 位小写 hex：{commit!r}"}
    project = normalize_project_from_repo(entry["repo_url"])
    co = tools.checkout(project, commit)
    if not co.ok:
        return {"status": "incorrect", "confidence": 0.90,
                "evidence": f"commit 在本地缓存中不可用：{co.error}"}
    return {"status": "correct", "confidence": 0.90,
            "evidence": f"commit {commit[:7]} 在本地缓存可用，且格式合规"}


def check_vuln_ids(
    entry: Dict[str, Any],
    advisory: Dict[str, Any],
) -> Dict[str, Any]:
    ids = entry.get("vuln_ids", []) or []
    if not ids:
        return {"status": "uncertain", "confidence": 0.50,
                "evidence": "vuln_ids 为空，需要公告或人工补全"}
    expected_cve = advisory.get("cve_id")
    expected_ghsa = advisory.get("ghsa_id")
    if expected_cve and expected_cve not in ids:
        return {"status": "incorrect", "confidence": 0.85,
                "evidence": f"vuln_ids 缺少公告中的 CVE：{expected_cve}"}
    if expected_ghsa and expected_ghsa not in ids:
        return {"status": "uncertain", "confidence": 0.55,
                "evidence": f"vuln_ids 缺少公告中的 GHSA：{expected_ghsa}"}
    return {"status": "correct", "confidence": 0.90,
            "evidence": f"vuln_ids={ids} 与公告一致"}


def check_vuln_title(
    entry: Dict[str, Any],
    advisory: Dict[str, Any],
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    expected = advisory.get("title", "")
    actual = entry.get("vuln_title", "")
    if not expected:
        return {"status": "uncertain", "confidence": 0.50,
                "evidence": "公告标题缺失，触发 LLM 语义判断"}
    prompt = (
        f"判断 vuln_title 是否正确。\n"
        f"advisory title: {expected}\n"
        f"actual: {actual}\n"
        f"返回 JSON：{{status,confidence,evidence}}"
    )
    out = llm.chat([LLMMessage("user", prompt)])
    try:
        import json
        data = json.loads(out)
        data.setdefault("status", "uncertain")
        data.setdefault("confidence", 0.50)
        data.setdefault("evidence", "LLM 语义判断")
        return data
    except Exception:
        # 回退：简单包含
        ok = expected[:10] in actual or actual[:10] in expected
        return {"status": "correct" if ok else "uncertain", "confidence": 0.50,
                "evidence": "LLM 输出解析失败，回退到关键词包含判断"}


def check_category(
    level: str,
    entry: Dict[str, Any],
    advisory: Dict[str, Any],
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    actual = entry.get(f"vuln_category_{level}", "")
    expected = advisory.get(f"vuln_category_{level}_hint", "")
    if not expected:
        return {"status": "uncertain", "confidence": 0.50,
                "evidence": f"公告未给出 l{level[-1]} 提示，需人工判定"}
    prompt = (
        f"判断 vuln_category_{level} 是否正确。\n"
        f"advisory_hint_l{level[-1]}: {expected}\n"
        f"actual: {actual}\n"
        f"返回 JSON：{{status,confidence,evidence}}"
    )
    out = llm.chat([LLMMessage("user", prompt)])
    try:
        import json
        data = json.loads(out)
        data.setdefault("status", "uncertain")
        data.setdefault("confidence", 0.50)
        data.setdefault("evidence", "LLM 语义判断")
        return data
    except Exception:
        return {"status": "uncertain", "confidence": 0.40,
                "evidence": "LLM 输出不可解析"}


def check_trace(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """trace 校验：每节点文件/行号/代码片段是否存在，再让 LLM 判断整体合理性。"""
    trace = entry.get("trace", []) or []
    if not trace:
        return {"status": "uncertain", "confidence": 0.40,
                "evidence": "trace 为空（可能合理，但无法验证）"}

    project = normalize_project_from_repo(entry["repo_url"])
    co = tools.checkout(project, entry["commit"])
    if not co.ok:
        return {"status": "incorrect", "confidence": 0.90,
                "evidence": f"trace 校验前置失败：{co.error}"}

    bad_nodes = []
    for idx, node in enumerate(trace):
        reads = tools.read_file_lines(co.data["cwd"], node["file"],
                                      *_line_range(node["line"]))
        if not reads.ok:
            bad_nodes.append(f"#{idx} 文件不存在 {node['file']}")
            continue
        actual = _norm_code(reads.data["snippet"])
        expected = _norm_code(node["code"])
        if expected not in actual and actual not in expected:
            bad_nodes.append(f"#{idx} {node['file']}:{node['line']} 代码片段不匹配")

    if bad_nodes:
        return {"status": "incorrect", "confidence": 0.85,
                "evidence": "trace 节点异常：" + "; ".join(bad_nodes[:3])}

    # 节点级都对，再让 LLM 判断"整体合理性"
    prompt = (
        f"trace 链路整体合理性判断。\n"
        f"entry_id: {entry.get('entry_id')}\n"
        f"trace 节点数: {len(trace)}\n"
        f"返回 JSON：{{status,confidence,evidence}}"
    )
    out = llm.chat([LLMMessage("user", prompt)])
    try:
        import json
        data = json.loads(out)
        data.setdefault("status", "uncertain")
        data.setdefault("confidence", 0.50)
        data.setdefault("evidence", "LLM 语义判断")
        return data
    except Exception:
        return {"status": "uncertain", "confidence": 0.50,
                "evidence": "LLM 输出不可解析"}


# ============================================================
# 汇总：跑一条 entry 的全部字段
# ============================================================
def check_all_fields(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """返回 fields dict + summary。"""
    advisory_result = tools.read_advisory(entry["report_id"])
    advisory = advisory_result.data if advisory_result.ok else {}

    fields: Dict[str, Dict[str, Any]] = {}
    fields["entry_point"] = check_entry_point(entry, tools, llm)
    fields["critical_operation"] = check_critical_operation(entry, tools, llm)
    fields["commit"] = check_commit(entry, tools)
    fields["vuln_ids"] = check_vuln_ids(entry, advisory) if advisory else {
        "status": "uncertain", "confidence": 0.40,
        "evidence": "公告缓存缺失，无法校验 vuln_ids",
    }
    fields["vuln_title"] = check_vuln_title(entry, advisory, llm) if advisory else {
        "status": "uncertain", "confidence": 0.40, "evidence": "公告缓存缺失",
    }
    fields["vuln_category_l1"] = check_category("l1", entry, advisory, llm) if advisory else {
        "status": "uncertain", "confidence": 0.40, "evidence": "公告缓存缺失",
    }
    fields["vuln_category_l2"] = check_category("l2", entry, advisory, llm) if advisory else {
        "status": "uncertain", "confidence": 0.40, "evidence": "公告缓存缺失",
    }
    fields["trace"] = check_trace(entry, tools, llm)

    # 整体 verdict：有一个 incorrect -> incorrect；全 correct -> correct；否则 uncertain
    statuses = [f["status"] for f in fields.values()]
    if "incorrect" in statuses:
        verdict = "incorrect"
    elif all(s == "correct" for s in statuses):
        verdict = "correct"
    else:
        verdict = "uncertain"

    incorrect_fields = [k for k, v in fields.items() if v["status"] == "incorrect"]
    summary = "整体判定为 {verdict}".format(verdict=verdict)
    if incorrect_fields:
        summary += f" — 异常字段: {', '.join(incorrect_fields)}"

    return {"verdict": verdict, "fields": fields, "summary": summary}
