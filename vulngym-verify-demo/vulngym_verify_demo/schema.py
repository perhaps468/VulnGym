# -*- coding: utf-8 -*-
"""Schema 校验与坏输入报告协议（I1 范围）。

本模块提供：
- `iter_jsonl_safe(path)`: 安全遍历 JSONL；坏 JSON 行不抛异常，生成稳定的
  ``__invalid_input__:<line_no>`` 占位符报告。
- `validate_entry(entry)`: 按 SCHEMA.md 校验 entry 全部必填字段、嵌套
  ``file/line/code``、line>0/合法 range、枚举与类型。
- `validate_report(report)`: 按 ``report_schema.json`` 校验 VerificationReport。
- `build_invalid_input_report(line_no, kind, message, ...)`:
  坏输入行报告工厂。
- `validate_evidence_ref(ref)`: 校验单个 ``evidence_refs`` 元素。
- `EvidenceRef`, `FieldResult`, `SelfCheck`, `Plan`, `ToolCall` 等 dataclass
  见 ``models.py``。

设计要点：
- 不抛未处理异常：每个校验函数返回 ``(ok, errors)``，调用方可决定如何处理。
- 禁止 SCHEMA.md 明确禁止的内部字段。
- 允许未知未来可选顶层字段（前向兼容）。
- 错误消息脱敏：不泄漏本地绝对路径。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union


# ============================================================
# SCHEMA.md 派生常量
# ============================================================

#: entries.jsonl 必填字段
ENTRY_REQUIRED_FIELDS: Tuple[str, ...] = (
    "entry_id",
    "report_id",
    "source_link",
    "vuln_ids",
    "origin",
    "project",
    "repo_url",
    "commit",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "entry_point",
    "critical_operation",
    "trace",
    "verify",
)

#: SCHEMA.md 明确禁止的内部字段（invariant #8）
FORBIDDEN_INTERNAL_FIELDS: frozenset = frozenset({
    "description",
    "human_remark",
    "pipeline_id",
    "annotated_by",
    "is_active",
    "created_at",
    "generality",
    "detection_type",
    "ground_truth",
    "taint_source",
    "taint_sink",
    "vuln_category_l3",
})

#: report 必填字段
REPORT_REQUIRED_TOP_FIELDS: Tuple[str, ...] = (
    "report_id",
    "entry_id",
    "verdict",
    "fields",
    "summary",
    "self_check",
    "plan",
    "tool_trace",
)

#: 8 个必填字段
ALL_EIGHT_FIELDS: Tuple[str, ...] = (
    "entry_point",
    "critical_operation",
    "commit",
    "vuln_ids",
    "vuln_title",
    "vuln_category_l1",
    "vuln_category_l2",
    "trace",
)

#: 状态三态
STATUS_VALUES: frozenset = frozenset({"correct", "incorrect", "uncertain"})

#: verdict 三态
VERDICT_VALUES: frozenset = frozenset({"correct", "incorrect", "uncertain"})

#: self_check.status 取值
SELF_CHECK_STATUS_VALUES: frozenset = frozenset({"completed", "skipped", "failed"})

#: evidence_refs.source 取值
EVIDENCE_SOURCE_VALUES: frozenset = frozenset({"advisory", "repository", "git"})

#: origin 常量（SCHEMA.md invariant #4）
ORIGIN_CONSTANT: str = "GitHub Advisory Database (reviewed)"

#: 合法工具名（tool_trace.tool）
TOOL_NAMES: frozenset = frozenset({
    "read_advisory",
    "checkout",
    "read_file_lines",
    "grep_code",
    "git_log",
})

#: commit 格式正则（40 位小写 hex）
COMMIT_RE = re.compile(r"[0-9a-f]{40}")

#: GHSA id 格式
GHSA_RE = re.compile(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}")

#: source_link 协议
SOURCE_LINK_PREFIX = "https://github.com/advisories/"


# ============================================================
# 行号校验
# ============================================================
def validate_line(value: Any) -> Tuple[bool, str]:
    """校验 entry_point/critical_operation/trace[*] 中的 line。

    返回 (ok, error_message)；合法时 error_message 为 ""。
    """
    if isinstance(value, bool):
        # bool 是 int 的子类，必须先排除
        return False, f"line must be int or 'start-end' string, got bool: {value!r}"
    if isinstance(value, int):
        if value < 1:
            return False, f"line must be >= 1, got {value}"
        return True, ""
    if isinstance(value, str):
        # 范围字符串 "start-end"
        if "-" not in value:
            return False, f"line string must be 'start-end' range, got {value!r}"
        parts = value.split("-")
        if len(parts) != 2:
            return False, f"line range must have exactly one '-', got {value!r}"
        try:
            start = int(parts[0])
            end = int(parts[1])
        except ValueError:
            return False, f"line range endpoints must be integers, got {value!r}"
        if start < 1 or end < 1:
            return False, f"line range endpoints must be >= 1, got {value!r}"
        if start > end:
            return False, f"line range start > end, got {value!r}"
        return True, ""
    return False, f"line must be int >= 1 or 'start-end' string, got {type(value).__name__}: {value!r}"


def normalize_line(value: Any) -> Optional[Tuple[int, int]]:
    """把 line 归一化为 (start, end) 元组。非法返回 None。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if value < 1:
            return None
        return (value, value)
    if isinstance(value, str) and "-" in value:
        try:
            parts = value.split("-")
            start = int(parts[0])
            end = int(parts[1])
            if start < 1 or end < 1 or start > end:
                return None
            return (start, end)
        except (ValueError, IndexError):
            return None
    return None


# ============================================================
# 节点校验（entry_point / critical_operation / trace[*]）
# ============================================================
def validate_node(node: Any, *, where: str) -> List[str]:
    """校验 entry_point/critical_operation/trace 节点。

    返回错误消息列表；空列表表示合法。
    ``where`` 仅用于错误消息上下文，例如 "entry_point" / "trace[2]"。
    """
    errors: List[str] = []
    if not isinstance(node, dict):
        return [f"{where}: expected object, got {type(node).__name__}"]
    for required in ("file", "line", "code"):
        if required not in node:
            errors.append(f"{where}: missing required field {required!r}")
    if "file" in node and not isinstance(node["file"], str):
        errors.append(f"{where}.file: expected string, got {type(node['file']).__name__}")
    if "code" in node and not isinstance(node["code"], str):
        errors.append(f"{where}.code: expected string, got {type(node['code']).__name__}")
    if "line" in node:
        ok, msg = validate_line(node["line"])
        if not ok:
            errors.append(f"{where}.line: {msg}")
    if "desc" in node and not isinstance(node["desc"], str):
        errors.append(f"{where}.desc: expected string, got {type(node['desc']).__name__}")
    return errors


# ============================================================
# Entry 校验（SCHEMA.md）
# ============================================================
def validate_entry(entry: Any) -> List[str]:
    """校验一条 entry。

    返回错误消息列表；空列表表示合法。
    """
    errors: List[str] = []
    if not isinstance(entry, dict):
        return [f"entry: expected object, got {type(entry).__name__}"]

    # 检查禁止字段
    for forbidden in FORBIDDEN_INTERNAL_FIELDS:
        if forbidden in entry:
            errors.append(f"entry: forbidden field {forbidden!r} (SCHEMA.md invariant #8)")

    # 必填字段
    for required in ENTRY_REQUIRED_FIELDS:
        if required not in entry:
            errors.append(f"entry: missing required field {required!r}")

    if errors:
        return errors

    # 类型与值校验
    if not isinstance(entry["entry_id"], str):
        errors.append("entry.entry_id: expected string")
    if not isinstance(entry["report_id"], str):
        errors.append("entry.report_id: expected string")
    if not isinstance(entry["source_link"], str):
        errors.append("entry.source_link: expected string")
    elif not entry["source_link"].startswith(SOURCE_LINK_PREFIX):
        errors.append(
            f"entry.source_link: must start with {SOURCE_LINK_PREFIX!r}, "
            f"got {entry['source_link']!r}"
        )
    if not isinstance(entry["vuln_ids"], list):
        errors.append("entry.vuln_ids: expected list of strings")
    else:
        for i, vid in enumerate(entry["vuln_ids"]):
            if not isinstance(vid, str):
                errors.append(f"entry.vuln_ids[{i}]: expected string")
    if entry.get("origin") != ORIGIN_CONSTANT:
        errors.append(
            f"entry.origin: must be {ORIGIN_CONSTANT!r} "
            f"(SCHEMA.md invariant #4), got {entry.get('origin')!r}"
        )
    if not isinstance(entry["project"], str):
        errors.append("entry.project: expected string")
    if not isinstance(entry["repo_url"], str):
        errors.append("entry.repo_url: expected string")
    elif not entry["repo_url"].startswith("https://github.com/"):
        errors.append(
            f"entry.repo_url: must start with 'https://github.com/', "
            f"got {entry['repo_url']!r}"
        )
    commit = entry.get("commit", "")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        errors.append(
            f"entry.commit: must be 40 lowercase hex chars, got {commit!r}"
        )
    if not isinstance(entry["vuln_title"], str):
        errors.append("entry.vuln_title: expected string")
    if not isinstance(entry["vuln_category_l1"], str):
        errors.append("entry.vuln_category_l1: expected string")
    if not isinstance(entry["vuln_category_l2"], str):
        errors.append("entry.vuln_category_l2: expected string")

    verify = entry.get("verify")
    if not isinstance(verify, int) or isinstance(verify, bool) or verify not in (0, 1):
        errors.append(f"entry.verify: must be 0 or 1, got {verify!r}")

    # 节点校验
    errors.extend(validate_node(entry.get("entry_point"), where="entry_point"))
    errors.extend(validate_node(entry.get("critical_operation"), where="critical_operation"))
    trace = entry.get("trace")
    if not isinstance(trace, list):
        errors.append("entry.trace: expected list")
    else:
        for i, node in enumerate(trace):
            errors.extend(validate_node(node, where=f"trace[{i}]"))

    return errors


# ============================================================
# EvidenceRef / FieldResult / ToolCall 校验
# ============================================================
def validate_evidence_ref(ref: Any) -> Tuple[bool, str]:
    """校验单个 evidence_refs 元素。"""
    if not isinstance(ref, dict):
        return False, f"evidence_ref must be object, got {type(ref).__name__}"
    if "source" not in ref:
        return False, "evidence_ref.source: missing"
    if ref["source"] not in EVIDENCE_SOURCE_VALUES:
        return False, f"evidence_ref.source: must be one of {sorted(EVIDENCE_SOURCE_VALUES)}"
    if "locator" not in ref or not isinstance(ref["locator"], str):
        return False, "evidence_ref.locator: missing or not string"
    if "quote" not in ref or not isinstance(ref["quote"], str):
        return False, "evidence_ref.quote: missing or not string"
    return True, ""


def validate_field_result(field_obj: Any, field_name: str) -> List[str]:
    """校验单个字段对象。"""
    errors: List[str] = []
    if not isinstance(field_obj, dict):
        return [f"fields.{field_name}: expected object, got {type(field_obj).__name__}"]
    if "status" not in field_obj or field_obj["status"] not in STATUS_VALUES:
        errors.append(
            f"fields.{field_name}.status: must be one of {sorted(STATUS_VALUES)}, "
            f"got {field_obj.get('status')!r}"
        )
    conf = field_obj.get("confidence")
    if not isinstance(conf, (int, float)) or isinstance(conf, bool):
        errors.append(f"fields.{field_name}.confidence: must be number, got {conf!r}")
    elif not (0.0 <= conf <= 1.0):
        errors.append(
            f"fields.{field_name}.confidence: must be in [0, 1], got {conf}"
        )
    if "evidence" not in field_obj or not isinstance(field_obj["evidence"], str):
        errors.append(f"fields.{field_name}.evidence: missing or not string")
    elif field_obj["evidence"] == "":
        # §4.1：无证据时 evidence_refs=[] 且 evidence 必须解释缺口
        errors.append(
            f"fields.{field_name}.evidence: must be non-empty when evidence_refs is empty (§4.1)"
        )
    refs = field_obj.get("evidence_refs", [])
    if not isinstance(refs, list):
        errors.append(f"fields.{field_name}.evidence_refs: expected list")
    else:
        for i, r in enumerate(refs):
            ok, msg = validate_evidence_ref(r)
            if not ok:
                errors.append(f"fields.{field_name}.evidence_refs[{i}]: {msg}")
    return errors


def validate_tool_call(call: Any) -> List[str]:
    """校验单条 tool_trace 条目。"""
    errors: List[str] = []
    if not isinstance(call, dict):
        return [f"tool_trace item: expected object, got {type(call).__name__}"]
    seq = call.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        errors.append(f"tool_trace[{seq}].seq: must be int >= 1, got {seq!r}")
    tool = call.get("tool")
    if not isinstance(tool, str):
        errors.append(f"tool_trace[?].tool: missing or not string")
    elif tool not in TOOL_NAMES:
        errors.append(f"tool_trace[?].tool: unknown tool {tool!r}, must be one of {sorted(TOOL_NAMES)}")
    if "input" in call and not isinstance(call["input"], dict):
        errors.append(f"tool_trace[?].input: must be object if present")
    if not isinstance(call.get("ok"), bool):
        errors.append(f"tool_trace[?].ok: must be bool")
    if "error" in call and call["error"] is not None and not isinstance(call["error"], str):
        errors.append(f"tool_trace[?].error: must be string or null")
    refs = call.get("evidence_refs", [])
    if not isinstance(refs, list):
        errors.append(f"tool_trace[?].evidence_refs: expected list of JSON paths")
    else:
        for i, r in enumerate(refs):
            if not isinstance(r, str):
                errors.append(f"tool_trace[?].evidence_refs[{i}]: must be string (JSON path)")
    return errors


def validate_self_check(sc: Any) -> List[str]:
    """校验 self_check 对象。"""
    errors: List[str] = []
    if not isinstance(sc, dict):
        return [f"self_check: expected object, got {type(sc).__name__}"]
    status = sc.get("status")
    if status not in SELF_CHECK_STATUS_VALUES:
        errors.append(
            f"self_check.status: must be one of {sorted(SELF_CHECK_STATUS_VALUES)}, got {status!r}"
        )
    if "agree" not in sc or not isinstance(sc["agree"], bool):
        errors.append("self_check.agree: missing or not bool")
    if status in ("failed", "skipped") and sc.get("agree") is not False:
        errors.append(
            f"self_check.agree: must be false when status={status!r} (§4.1)"
        )
    if "comment" not in sc or not isinstance(sc["comment"], str):
        errors.append("self_check.comment: missing or not string")
    cf = sc.get("checked_fields", [])
    if not isinstance(cf, list):
        errors.append("self_check.checked_fields: expected list")
    else:
        for i, f in enumerate(cf):
            if not isinstance(f, str):
                errors.append(f"self_check.checked_fields[{i}]: must be string")
    return errors


def validate_plan(plan: Any) -> List[str]:
    """校验 plan 对象。"""
    errors: List[str] = []
    if not isinstance(plan, dict):
        return [f"plan: expected object, got {type(plan).__name__}"]
    if plan.get("version") != "1":
        errors.append(f"plan.version: must be '1', got {plan.get('version')!r}")
    for key in ("tools_planned", "fields_planned"):
        v = plan.get(key)
        if not isinstance(v, list):
            errors.append(f"plan.{key}: expected list")
        else:
            for i, x in enumerate(v):
                if not isinstance(x, str):
                    errors.append(f"plan.{key}[{i}]: must be string")
    return errors


# ============================================================
# VerificationReport 校验
# ============================================================
def validate_report(report: Any) -> List[str]:
    """校验一条 VerificationReport。"""
    errors: List[str] = []
    if not isinstance(report, dict):
        return [f"report: expected object, got {type(report).__name__}"]

    for required in REPORT_REQUIRED_TOP_FIELDS:
        if required not in report:
            errors.append(f"report: missing required top-level field {required!r}")

    if errors:
        return errors

    # report_id / entry_id
    if not isinstance(report.get("report_id"), str):
        errors.append("report.report_id: expected string")
    if not isinstance(report.get("entry_id"), str):
        errors.append("report.entry_id: expected string")

    # verdict
    if report.get("verdict") not in VERDICT_VALUES:
        errors.append(
            f"report.verdict: must be one of {sorted(VERDICT_VALUES)}, "
            f"got {report.get('verdict')!r}"
        )

    # summary
    if not isinstance(report.get("summary"), str):
        errors.append("report.summary: expected string")

    # fields
    fields_obj = report.get("fields")
    if not isinstance(fields_obj, dict):
        errors.append(f"report.fields: expected object, got {type(fields_obj).__name__}")
    else:
        for fname in ALL_EIGHT_FIELDS:
            errors.extend(validate_field_result(fields_obj.get(fname), fname))

    # self_check / plan
    errors.extend(validate_self_check(report.get("self_check")))
    errors.extend(validate_plan(report.get("plan")))

    # tool_trace
    tt = report.get("tool_trace")
    if not isinstance(tt, list):
        errors.append("report.tool_trace: expected list")
    else:
        for i, call in enumerate(tt):
            errs = validate_tool_call(call)
            errors.extend(f"tool_trace[{i}].{e}" if not e.startswith("tool_trace[") else e for e in errs)

    # input_error（可选但若存在必须符合）
    if "input_error" in report:
        ie = report["input_error"]
        if not isinstance(ie, dict):
            errors.append("report.input_error: expected object")
        else:
            if not isinstance(ie.get("line_no"), int) or ie.get("line_no", 0) < 1:
                errors.append("report.input_error.line_no: must be int >= 1")
            if not isinstance(ie.get("kind"), str):
                errors.append("report.input_error.kind: expected string")
            if not isinstance(ie.get("message"), str):
                errors.append("report.input_error.message: expected string")

    return errors


# ============================================================
# 坏输入报告工厂
# ============================================================
def invalid_input_id(line_no: int) -> str:
    """生成稳定的坏输入占位符 ID。"""
    return f"__invalid_input__:{line_no}"


def build_invalid_input_field() -> Dict[str, Any]:
    """坏输入行的字段统一填 uncertain。"""
    return {
        "status": "uncertain",
        "confidence": 0.0,
        "evidence": (
            "input row could not be parsed; "
            "all 8 fields inherit uncertain until input is repaired."
        ),
        "evidence_refs": [],
    }


def build_invalid_input_report(
    line_no: int,
    kind: str,
    message: str,
) -> Dict[str, Any]:
    """工厂：构造坏输入行的标准 uncertain 报告。

    参数：
        line_no: 输入 JSONL 文件中的 1-based 行号
        kind: 'json_parse_error' | 'schema_violation' | 'missing_field' | 'forbidden_field'
        message: 脱敏后的错误消息（不包含本地绝对路径）
    """
    placeholder_id = invalid_input_id(line_no)
    fields = {fname: build_invalid_input_field() for fname in ALL_EIGHT_FIELDS}
    return {
        "report_id": placeholder_id,
        "entry_id": placeholder_id,
        "verdict": "uncertain",
        "fields": fields,
        "summary": f"input row {line_no} invalid: {kind}",
        "self_check": {
            "status": "skipped",
            "agree": False,
            "comment": "self-check skipped because input row was not parseable",
            "checked_fields": [],
        },
        "plan": {
            "version": "1",
            "tools_planned": [],
            "fields_planned": list(ALL_EIGHT_FIELDS),
        },
        "tool_trace": [],
        "input_error": {
            "line_no": line_no,
            "kind": kind,
            "message": message,
        },
    }


# ============================================================
# Safe JSONL 迭代器
# ============================================================
def _sanitize_message(msg: str) -> str:
    """脱敏：移除本地绝对路径与 API key 风格字符串。

    仅保留错误类型与必要上下文，避免泄漏 ``C:\\...`` 或 ``/home/...`` 等。
    """
    # Windows 绝对路径
    msg = re.sub(r"[A-Za-z]:\\\\[^\s\"']+", "<abspath>", msg)
    msg = re.sub(r"[A-Za-z]:/[^\s\"']+", "<abspath>", msg)
    # POSIX 绝对路径
    msg = re.sub(r"/(?:home|Users|var|tmp|opt|root)/[^\s\"']+", "<abspath>", msg)
    # API key 风格长 hex/base64 串（保守触发：连续 32+ 字符的 hex/base64）
    msg = re.sub(r"\b[A-Za-z0-9_-]{32,}\b", "<redacted>", msg)
    return msg


def iter_jsonl_safe(path: Path) -> Iterator[Union[Dict[str, Any], Tuple[int, str]]]:
    """安全遍历 JSONL 文件。

    生成器产出：
        - 合法行：原始 dict
        - 坏 JSON 行：(line_no, error_message) 元组；调用方负责转换为报告
    """
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, start=1):
            stripped = raw.strip()
            if not stripped:
                # 空行：跳过，不产生报告
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as e:
                yield (line_no, _sanitize_message(str(e)))
                continue
            yield obj


def read_jsonl_with_reports(path: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """读取 JSONL，分别返回合法 entry 与坏输入报告。

    返回 (entries, invalid_reports)：
        - entries: 通过 JSON 解析的 list（**未做 SCHEMA.md 校验**）
        - invalid_reports: 已经按 ``build_invalid_input_report`` 生成的标准报告
    """
    entries: List[Dict[str, Any]] = []
    invalid: List[Dict[str, Any]] = []
    for item in iter_jsonl_safe(Path(path)):
        if isinstance(item, tuple):
            line_no, msg = item
            invalid.append(build_invalid_input_report(line_no, "json_parse_error", msg))
        else:
            entries.append(item)
    return entries, invalid
