# -*- coding: utf-8 -*-
"""Agent 主循环（per entry）：

1. 规划阶段：列举本 entry 要核验的字段，列出将调用的工具
2. 工具调用阶段：执行 tools / 调 LLM 完成字段判定，并真实记录 tool_trace
3. 反思阶段：让 LLM 对全部字段判定做一次 self-check，必要时修正

返回结构对齐 VulnGym 考题要求 + I1 report_schema.json：
    {
      "report_id": ...,
      "entry_id": ...,
      "verdict":  correct | incorrect | uncertain,
      "fields": { field: {status, confidence, evidence, evidence_refs} },
      "summary": "...",
      "self_check": {status, agree, comment, checked_fields},
      "plan": {version, entry_id, report_id, tools_planned, fields_planned},
      "tool_trace": [{seq, tool, input, ok, error, evidence_refs}, ...]
    }

I5 契约（来自 I5_START_HANDBOOK §3）：
  * plan.version 必须 "1"
  * tool_trace 至少包含 advisory / repository / git 三类工具调用（每类 ≥1）
  * self_check 四键：status/agree/comment/checked_fields；
    status=skipped|failed 时 agree 强制 false
  * tool_trace 失败也记录（ok=false + error），不抛未处理异常
  * 不修改 field_checkers / llm_client / prompts / tools / schema / report_schema
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .field_checkers import check_all_fields
from .llm_client import BaseLLMClient, LLMMessage, redact_text
from .tools import ToolResult, VulnGymTools, normalize_project_from_repo


# ============================================================
# Constants
# ============================================================

#: I1 schema 定义的 8 个必填字段名（与 ALL_EIGHT_FIELDS 同源，但 agent.py 不 import
#: schema.py 以避免循环导入；保持本地常量便于测试 import）
EIGHT_FIELDS: List[str] = [
    "entry_point",
    "critical_operation",
    "commit",
    "vuln_ids",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "trace",
]

#: 工具所属类别（用于构建 tool_trace 时分类审计）
_TOOL_CATEGORY = {
    "read_advisory": "advisory",
    "checkout": "git",
    "read_file_lines": "repository",
    "grep_code": "repository",
    "git_log": "git",
}


# ============================================================
# Internal helpers
# ============================================================


def _short_commit(commit: str, limit: int = 12) -> str:
    """截断 commit 用于 trace.input（脱敏 + 防长 hex 触发 redact）。"""
    if not commit:
        return ""
    if len(commit) <= limit:
        return commit
    return commit[:limit] + "…"


def _empty_tool_result(name: str = "") -> ToolResult:
    """构造一个 ok=false 的空 ToolResult（用于前置失败时占位）。"""
    return ToolResult(name=name, ok=False, data=None, error="not invoked (prerequisite failed)")


def _safe_file_in_trace(entry: Dict[str, Any]) -> Optional[str]:
    """从 entry 中提取 trace.input.file 字段（脱敏后只保留 file 相对路径）。"""
    verify = entry.get("verify") or {}
    if not isinstance(verify, dict):
        return None
    return verify.get("file")


# ============================================================
# plan_for_entry
# ============================================================


def plan_for_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """返回规划结果：列出要调用的工具和要核验的字段。

    I5 契约：必须含 version="1" + tools_planned + fields_planned 三键；
    tools_planned 至少覆盖 advisory/repository/git 三类。
    """
    return {
        "version": "1",
        "entry_id": entry.get("entry_id"),
        "report_id": entry.get("report_id"),
        "tools_planned": [
            "read_advisory",      # advisory
            "checkout",           # git
            "read_file_lines",    # repository
            "grep_code",          # repository
            "git_log",            # git
        ],
        "fields_planned": list(EIGHT_FIELDS),
    }


# ============================================================
# tool_trace 构造
# ============================================================


def _record(seq_ref: List[int], tool: str, input_payload: Dict[str, Any], result: ToolResult) -> Dict[str, Any]:
    """记录一次工具调用并递增 seq。"""
    seq_ref[0] += 1
    return {
        "seq": seq_ref[0],
        "tool": tool,
        "input": input_payload,
        "ok": bool(getattr(result, "ok", False)),
        "error": getattr(result, "error", None),
        "evidence_refs": [],
    }


def _build_tool_trace(entry: Dict[str, Any], tools: VulnGymTools) -> List[Dict[str, Any]]:
    """运行时审计：每条 entry 强制调用 3 类工具（advisory/repository/git）。

    - 失败也记录（ok=false + error），**不**抛未处理异常
    - input 仅含脱敏后的摘要（commit 取前 12 字符；绝对路径由 tools 内部已脱敏）
    - evidence_refs 留空，由 verify_entry 在写入 fields 后回填 JSON 路径
    """
    trace: List[Dict[str, Any]] = []
    seq_ref = [0]  # 用 list 包装以便闭包修改
    repo_url = entry.get("repo_url", "")
    report_id = entry.get("report_id") or ""

    # ---- 1. advisory（必含，至少 1 次）----
    if report_id:
        adv_input: Dict[str, Any] = {"report_id": report_id}
        try:
            adv_res = tools.read_advisory(report_id)
        except Exception as exc:  # pragma: no cover — 防御性兜底
            adv_res = ToolResult(
                "read_advisory", False, None,
                f"read_advisory raised: {type(exc).__name__}: {str(exc)[:120]}",
            )
        trace.append(_record(seq_ref, "read_advisory", adv_input, adv_res))
    else:
        trace.append(_record(seq_ref, "read_advisory", {}, _empty_tool_result("read_advisory")))

    # ---- 解析 commit / project，给后续 git + repository 步骤复用 ----
    verify = entry.get("verify") or {}
    commit = verify.get("commit") if isinstance(verify, dict) else None
    if not commit:
        commit = entry.get("commit")
    commit_valid = isinstance(commit, str) and len(commit) == 40

    project = ""
    if commit_valid:
        try:
            project = normalize_project_from_repo(repo_url)
        except Exception:
            project = ""

    # ---- 2. git（必含，commit checkout）----
    if commit_valid:
        try:
            co_res = tools.checkout(project, commit) if project else _empty_tool_result("checkout")
        except Exception as exc:  # pragma: no cover — 防御性兜底
            co_res = ToolResult(
                "checkout", False, None,
                f"checkout raised: {type(exc).__name__}: {str(exc)[:120]}",
            )
        trace.append(_record(
            seq_ref,
            "checkout",
            {"project": project, "commit": _short_commit(commit)},
            co_res,
        ))
    else:
        trace.append(_record(seq_ref, "checkout", {}, _empty_tool_result("checkout")))

    # ---- 3. repository（必含，至少 1 次；read_file_lines）----
    rel_file = _safe_file_in_trace(entry) or ""
    if commit_valid and project and rel_file:
        # 用 checkout 的 cwd 作为 read_file_lines 的 cwd
        cwd = str(tools.repo_cache_dir / project / commit)
        try:
            rdl_res = tools.read_file_lines(cwd, rel_file, 1, 10**9)
        except Exception as exc:  # pragma: no cover
            rdl_res = ToolResult(
                "read_file_lines", False, None,
                f"read_file_lines raised: {type(exc).__name__}: {str(exc)[:120]}",
            )
        trace.append(_record(
            seq_ref,
            "read_file_lines",
            {"file": rel_file, "commit": _short_commit(commit)},
            rdl_res,
        ))
    else:
        trace.append(_record(
            seq_ref,
            "read_file_lines",
            {"file": rel_file} if rel_file else {},
            _empty_tool_result("read_file_lines"),
        ))

    return trace


# ============================================================
# trace.evidence_refs 回填
# ============================================================


def _link_trace_to_fields(
    trace: List[Dict[str, Any]],
    fields_result: Dict[str, Dict[str, Any]],
) -> None:
    """把每条 trace 的 tool 与字段 evidence 路径挂钩。

    规则：
      * read_advisory → 所有有 evidence 的字段（公告相关）
      * checkout / git_log → 所有字段（git 类别）
      * read_file_lines / grep_code → 所有字段（repository 类别）

    实际回填采用 JSON 路径（fields.<name>.evidence）。每个 trace 的
    evidence_refs 字段被原地写入字符串列表（I1 schema ToolCall.evidence_refs
    = list[str]）。
    """
    if not trace or not fields_result:
        return

    # 按字段收集 evidence 路径
    paths = ["fields.{}.evidence".format(name) for name in fields_result.keys()]

    for entry in trace:
        tool_name = entry.get("tool", "")
        if not tool_name:
            continue
        # 所有工具都挂全部字段路径（保守策略，避免漏挂）
        # 但同字段同一工具多次出现会重复，先去重
        seen = set()
        refs: List[str] = []
        for p in paths:
            key = (tool_name, p)
            if key not in seen:
                seen.add(key)
                refs.append(p)
        entry["evidence_refs"] = refs


# ============================================================
# self-check
# ============================================================


def self_check(
    entry: Dict[str, Any],
    fields_result: Dict[str, Dict[str, Any]],
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """反思层：让 LLM 反向复核本条 entry 的全部字段判定。

    I5 契约（对齐 I1 schema SelfCheck）：
      - 必须含 status/agree/comment/checked_fields 四键
      - status ∈ {completed, skipped, failed}
      - status ∈ {skipped, failed} → agree 必须 false
      - comment 必须非空（I1 schema 隐式约束：comment 是 string）
      - completed 路径下 agree 由 LLM 决定（不得人为强制 true）
    """
    checked_fields = list(fields_result.keys())
    # 用 ensure_ascii=False 保留中文字段名，方便 LLM 直观阅读
    prompt = (
        "请复核下列字段判定。检查证据是否自洽，是否有遗漏或过度判定。\n"
        f"entry_id: {entry.get('entry_id')}\n"
        f"fields: {json.dumps(fields_result, ensure_ascii=False)}\n"
        '返回 JSON：{"agree": true|false, "comment": "..."}'
    )
    try:
        out = llm.chat([LLMMessage("user", prompt)])
        parsed = json.loads(out)
        if not isinstance(parsed, dict):
            raise ValueError(f"self-check returned non-dict: {type(parsed).__name__}")
        agree_raw = parsed.get("agree", False)
        if not isinstance(agree_raw, bool):
            raise ValueError(f"self-check agree not bool: {type(agree_raw).__name__}")
        comment_raw = parsed.get("comment", "")
        if not isinstance(comment_raw, str):
            comment_raw = str(comment_raw)
        return {
            "status": "completed",
            "agree": agree_raw,
            "comment": redact_text(comment_raw.strip()) or "self-check completed",
            "checked_fields": checked_fields,
        }
    except Exception as exc:
        # 兜底返回：网络抖动/限流/不可解析时不让主流程崩。
        # I5 契约：skipped → agree 必须 false
        return {
            "status": "skipped",
            "agree": False,
            "comment": f"self-check skipped: {redact_text(str(exc))[:120]}",
            "checked_fields": checked_fields,
        }


# ============================================================
# verify_entry / verify_entries
# ============================================================


def verify_entry(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
    verbose: bool = False,
) -> Dict[str, Any]:
    """跑完一条 entry，返回报告 dict。

    I5 契约：
      - 返回 dict 必含 report_id / entry_id / verdict / fields / summary /
        self_check / plan / tool_trace（与 I1 schema 对齐）
      - tool_trace 至少含 advisory / repository / git 三类工具
      - self_check 必含 status/agree/comment/checked_fields 四键
      - plan.version == "1"
      - 坏 commit / 缺 report_id 等异常输入也生成报告，不抛未处理异常
    """
    plan = plan_for_entry(entry)
    if verbose:
        print(f"  [plan] {plan}")

    # 第一阶段：先跑工具和字段判定，拿到“初判结果”。
    # 这里会把 entry_point / critical_operation / trace 等字段全部过一遍。
    try:
        fields_result_bundle = check_all_fields(entry, tools, llm)
    except Exception as exc:
        # I5 契约：坏输入不能阻塞主流程，构造 8 字段 uncertain 报告
        return _fallback_error_report(
            entry=entry,
            plan=plan,
            phase="check_all_fields",
            exc=exc,
            tools=tools,
        )

    fields_result = fields_result_bundle["fields"]

    # 第二阶段：构造并回填 tool_trace
    trace = _build_tool_trace(entry, tools)
    _link_trace_to_fields(trace, fields_result)

    # 第三阶段：把初判结果交给 self_check 做二次复核
    review = self_check(entry, fields_result, llm)

    # 第四阶段：聚合 verdict / fields / summary / self_check / plan / tool_trace
    return {
        "report_id": entry.get("report_id"),
        "entry_id": entry.get("entry_id"),
        "verdict": fields_result_bundle["verdict"],
        "fields": fields_result,
        "summary": fields_result_bundle["summary"],
        "self_check": review,
        "plan": plan,
        "tool_trace": trace,
    }


def _fallback_error_report(
    entry: Dict[str, Any],
    plan: Dict[str, Any],
    phase: str,
    exc: BaseException,
    tools: VulnGymTools,
) -> Dict[str, Any]:
    """当 check_all_fields 抛异常时构造的标准 uncertain 报告。

    - 8 字段全 uncertain + 解释缺口
    - tool_trace 仍记录 3 类工具（advisory + git + repository 各 1 次）
    - self_check 走 skipped 路径，agree=false
    """
    fields = {
        name: {
            "status": "uncertain",
            "confidence": 0.0,
            "evidence": (
                f"agent-level fallback: {phase} raised "
                f"{type(exc).__name__}; all 8 fields inherit uncertain."
            ),
            "evidence_refs": [],
        }
        for name in EIGHT_FIELDS
    }

    trace = _build_tool_trace(entry, tools)
    _link_trace_to_fields(trace, fields)

    return {
        "report_id": entry.get("report_id"),
        "entry_id": entry.get("entry_id"),
        "verdict": "uncertain",
        "fields": fields,
        "summary": f"agent-level fallback: {phase} raised {type(exc).__name__}",
        "self_check": {
            "status": "skipped",
            "agree": False,
            "comment": f"self-check skipped due to agent-level error: {redact_text(str(exc))[:120]}",
            "checked_fields": list(EIGHT_FIELDS),
        },
        "plan": plan,
        "tool_trace": trace,
    }


def _make_empty_fields(evidence: str) -> Dict[str, Dict[str, Any]]:
    """生成 8 个空字段，全部 uncertain。"""
    field_names = ["entry_point", "critical_operation", "commit", "vuln_ids", 
                   "vuln_title", "vuln_category_l1", "vuln_category_l2", "trace"]
    return {
        name: {
            "status": "uncertain",
            "confidence": 0.0,
            "evidence": evidence,
            "evidence_refs": []
        }
        for name in field_names
    }


def verify_entries(
    entries: List[Dict[str, Any]],
    tools: VulnGymTools,
    llm: BaseLLMClient,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    """逐条 entry 跑 verify_entry，汇总成报告列表。

    - 顺序处理（I5 不并发）
    - 任何一条失败不中断后续
    - verbose=True 时打印进度与判定摘要
    - I6：坏 JSON / 缺字段生成 __invalid_input__ 报告
    """
    reports: List[Dict[str, Any]] = []
    for i, entry in enumerate(entries):
        # ---- I6: 检测解析错误 ----
        if entry.get("__parse_error__"):
            line_no = entry.get("__line_no__", i)
            report = {
                "report_id": f"__invalid_input__:{line_no}",
                "entry_id": f"__invalid_input__:{line_no}",
                "verdict": "uncertain",
                "input_error": {
                    "line_no": line_no,
                    "kind": "json_parse_error",
                    "message": entry.get("__error_message__", "unknown")
                },
                "fields": _make_empty_fields("输入行解析失败"),
                "summary": f"输入行 {line_no} JSON 解析失败",
                "self_check": {"status": "skipped", "agree": False, "comment": "输入无效", "checked_fields": []},
                "plan": {},
                "tool_trace": []
            }
            reports.append(report)
            if verbose:
                print(f"  [skip] line {line_no}: parse error")
            continue
        
        # ---- I6: 检测缺字段 ----
        required = ["report_id", "commit", "entry_point", "critical_operation"]
        missing = [k for k in required if k not in entry]
        if missing:
            entry_id = entry.get("entry_id", f"__invalid_input__:{i+1}")
            report = {
                "report_id": entry.get("report_id", f"__invalid_input__:{i+1}"),
                "entry_id": entry_id,
                "verdict": "uncertain",
                "input_error": {
                    "line_no": i + 1,
                    "kind": "missing_required_field",
                    "message": f"缺少必填字段: {missing}"
                },
                "fields": _make_empty_fields(f"缺少必填字段: {missing}"),
                "summary": f"缺少必填字段: {', '.join(missing)}",
                "self_check": {"status": "skipped", "agree": False, "comment": "输入不完整", "checked_fields": []},
                "plan": {},
                "tool_trace": []
            }
            reports.append(report)
            if verbose:
                print(f"  [skip] {entry_id}: missing fields {missing}")
            continue
        
        # ---- 原有正常处理逻辑 ----
        if verbose:
            print(f"\n=== entry {i + 1}/{len(entries)}: {entry.get('entry_id')} / {entry.get('report_id')} ===")
        try:
            rep = verify_entry(entry, tools, llm, verbose=verbose)
        except Exception as exc:
            # 兜底：即使 verify_entry 自己抛了也不中断主流程
            rep = _fallback_error_report(
                entry=entry or {},
                plan=plan_for_entry(entry or {}),
                phase="verify_entry",
                exc=exc,
                tools=tools,
            )
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


# ============================================================
# Internal accessor：允许 tests / 上层扩展
# ============================================================


def get_eight_fields() -> List[str]:
    """返回 I1 schema 定义的 8 字段名列表（供测试/调用方复用）。"""
    return list(EIGHT_FIELDS)


def get_tool_category(tool_name: str) -> Optional[str]:
    """返回工具所属的 source 类别（advisory/repository/git）。"""
    return _TOOL_CATEGORY.get(tool_name)