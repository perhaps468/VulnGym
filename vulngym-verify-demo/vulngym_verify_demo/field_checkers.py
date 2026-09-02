# -*- coding: utf-8 -*-
"""字段级三态判定：entry_point / critical_operation / vuln_ids / commit /
vuln_title / vuln_category_l1 / vuln_category_l2 / trace。

每个 check_field_X 返回：
    {
      "status":     "correct" | "incorrect" | "uncertain",
      "confidence": float in [0, 1],
      "evidence":   一句话以上，引用工具返回的具体内容
      "evidence_refs": List[Dict[str, str]]   # I3 新增 — I1 schema 已冻结字段
    }

策略：
- 优先用工具做确定性检查（grep_code / read_file_lines）
- 信息不足或需要语义理解时调用 LLM（带 mock fallback）

I3 升级：
  * 每个 check_field_X 填充 evidence_refs:
    - 确定性字段（entry_point / critical_operation / commit / trace）：repository / git
    - 公告相关字段（vuln_ids / title / category_l1 / l2）：advisory
  * check_all_fields 汇总逻辑**不改**（ISSUE_OUTLINE §5 I3 明确约束）
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .llm_client import BaseLLMClient, LLMMessage, parse_structured_response
from .tools import ToolResult, VulnGymTools, normalize_project_from_repo
from .prompts import (
    TRACE_OVERALL_PROMPT,
    VULN_TITLE_PROMPT,
    vuln_category_prompt,
)
# 避免循环导入：models.py 末尾会 import field_checkers，所以这里不能用
# `from .models import EvidenceRef`。直接用具名字典构造（schema.py §4.1
# 与 validate_evidence_ref 完全兼容），并在 to_dict 输出时保持同构。


# ============================================================
# EvidenceRef 工厂函数（I3 新增）
# ============================================================


def _ref_repo(file: str, commit: str, line_spec: Any, quote: str) -> Dict[str, str]:
    """构造 repository 类型引用 dict（与 EvidenceRef.to_dict() 同构）。

    locator 格式: <commit[:7]>:<file>:<line>
    quote 截断到 80 字符（schema.py §4.1 限制）
    """
    locator = "{}:{}:{}".format(commit[:7], file, line_spec)
    q = (quote or "").strip()
    if len(q) > 80:
        q = q[:80]
    return {"source": "repository", "locator": locator, "quote": q}


def _ref_git(project: str, commit: str, sha_or_message: str, quote: str = "") -> Dict[str, str]:
    """构造 git 类型引用 dict。

    locator 格式: <project>/<commit[:7]>:<sha_or_message>
    """
    locator = "{}/{}:{}".format(project, commit[:7], sha_or_message)
    q = (quote or "").strip()
    if len(q) > 80:
        q = q[:80]
    return {"source": "git", "locator": locator, "quote": q}


def _ref_advisory(advisory_locator: str, quote: str) -> Dict[str, str]:
    """构造 advisory 类型引用 dict。

    locator 格式: advisory.json#<json_path>
    """
    q = (quote or "").strip()
    if len(q) > 80:
        q = q[:80]
    return {"source": "advisory", "locator": advisory_locator, "quote": q}


# ---------- 辅助：line 归一化 ----------
def _line_range(value: Any) -> Tuple[int, int]:
    """把 int 或 "a-b" 转成 (start, end)。"""
    if isinstance(value, int):
        return (value, value)
    if isinstance(value, str) and "-" in value:
        a, b = value.split("-", 1)
        return (int(a), int(b))
    raise ValueError(f"bad line spec: {value!r}")


def _line_spec_repr(value: Any) -> str:
    """把 line spec 序列化成 locator 用字符串。"""
    if isinstance(value, int):
        return str(value)
    return str(value)


def _norm_code(code: str) -> str:
    # 归一化工具 1/2：把连续空白(空格/制表/换行)折叠成单空格
    # 目的：实测代码和标注代码常常只是缩进/换行不同，归一化后方便做包含判定
    return re.sub(r"\s+", " ", (code or "").strip())


# ============================================================
# I3 Layer-3: 版本号解析与公告范围判定（I3 启动手册 §5 验收 2-3）
# ============================================================

_VERSION_RX = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?")


def _parse_version(s: Any) -> Optional[Tuple[int, int, int]]:
    """解析 '1.4.2' / 'v0.1.4' 为 (1,4,2) 元组；不可解析返回 None。"""
    if not s or not isinstance(s, str):
        return None
    m = _VERSION_RX.fullmatch(s.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _version_cmp(a: Any, b: Any) -> Optional[int]:
    """比较两个版本；不可解析返回 None。"""
    va, vb = _parse_version(a), _parse_version(b)
    if va is None or vb is None:
        return None
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def _version_is_affected(version: Any, affected_versions: Any) -> Optional[bool]:
    """判定 version 是否落在 affected_versions 任何一个区间内。

    返回：
        True  - 落在区间（受影响）
        False - 全部区间都不命中（不受影响）
        None  - 无法判定（区间格式未知或 version 无法解析）

    仅支持 ``< X.Y.Z`` 形式（与 mock advisories 当前形态一致）。
    """
    if not version or not affected_versions or not isinstance(affected_versions, list):
        return None
    any_decidable = False
    for spec in affected_versions:
        if not isinstance(spec, str):
            return None
        spec = spec.strip()
        if spec.startswith("< "):
            threshold = spec[2:].strip()
            c = _version_cmp(version, threshold)
            if c is not None:
                any_decidable = True
                if c < 0:
                    return True
        else:
            # 不支持的范围表达式（如 "<="、">"、"="）→ 视为不可判定
            return None
    if any_decidable:
        return False
    return None


def _version_meets_or_exceeds(version: Any, threshold: Any) -> Optional[bool]:
    """判定 version >= threshold；不可解析返回 None。"""
    if not version or not threshold:
        return None
    c = _version_cmp(version, threshold)
    if c is None:
        return None
    return c >= 0


def _merge_refs(*ref_lists: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """按 (source, locator, quote) 三键去重合并多组 refs。"""
    out: List[Dict[str, str]] = []
    seen: set = set()
    for refs in ref_lists:
        if not refs:
            continue
        for r in refs:
            if not isinstance(r, dict):
                continue
            key = (r.get("source"), r.get("locator"), r.get("quote"))
            if key not in seen:
                out.append(r)
                seen.add(key)
    return out


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
                "evidence": f"无法 checkout 到 commit={commit[:7]}：{co.error}",
                "evidence_refs": []}

    reads = tools.read_file_lines(co.data["cwd"], ep["file"],
                                  *_line_range(ep["line"]))
    if not reads.ok:
        # 文件根本不存在 -> 明确 incorrect（典型数据脏）
        return {"status": "incorrect", "confidence": 0.95,
                "evidence": f"文件不存在：{ep['file']}（{reads.error}）",
                "evidence_refs": [_ref_repo(ep["file"], commit, ep["line"],
                                            f"file not found: {ep['file']}")]}

    snippet = reads.data["snippet"]
    actual = _norm_code(snippet)
    expected = _norm_code(ep["code"])
    refs: List[Dict[str, str]] = [
        _ref_repo(ep["file"], commit, ep["line"], snippet),
    ]
    # 允许"标注代码是实测代码的子串"或反过来，兼容多行截取差异。
    if expected in actual or actual in expected:
        return {"status": "correct", "confidence": 0.90,
                "evidence": f"checkout 后 {ep['file']}:{ep['line']} 代码片段匹配 (snippet={snippet.strip()[:120]})",
                "evidence_refs": refs}

    # 第二层：行号可能因为 commit 漂移或标注误差发生偏移，尝试局部窗口复核。
    s, e = _line_range(ep["line"])
    near_start, near_end = max(1, s - 5), e + 5
    near = tools.read_file_lines(co.data["cwd"], ep["file"], near_start, near_end)
    if near.ok and expected in _norm_code(near.data["snippet"]):
        return {"status": "uncertain", "confidence": 0.55,
                "evidence": f"行号偏移：在 {near_start}-{near_end} 范围内找到匹配代码片段，但原 line {ep['line']} 不匹配",
                "evidence_refs": refs + [
                    _ref_repo(ep["file"], commit,
                              f"{near_start}-{near_end}",
                              near.data["snippet"]),
                ]}

    return {"status": "incorrect", "confidence": 0.85,
            "evidence": f"代码片段不匹配：actual={actual[:80]} expected={expected[:80]}",
            "evidence_refs": refs}


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
                "evidence": f"无法 checkout：{co.error}",
                "evidence_refs": []}

    reads = tools.read_file_lines(co.data["cwd"], co_field["file"],
                                  *_line_range(co_field["line"]))
    if not reads.ok:
        return {"status": "incorrect", "confidence": 0.95,
                "evidence": f"critical_operation 文件不存在：{co_field['file']}",
                "evidence_refs": [_ref_repo(co_field["file"], commit, co_field["line"],
                                            f"file not found: {co_field['file']}")]}

    actual = _norm_code(reads.data["snippet"])
    expected = _norm_code(co_field["code"])
    refs: List[Dict[str, str]] = [
        _ref_repo(co_field["file"], commit, co_field["line"], reads.data["snippet"]),
    ]
    if expected in actual or actual in expected:
        return {"status": "correct", "confidence": 0.90,
                "evidence": f"checkout 后 {co_field['file']}:{co_field['line']} 匹配 (snippet={reads.data['snippet'].strip()[:120]})",
                "evidence_refs": refs}

    # 临近窗口搜索
    s, e = _line_range(co_field["line"])
    near = tools.read_file_lines(co.data["cwd"], co_field["file"], max(1, s - 5), e + 5)
    if near.ok and expected in _norm_code(near.data["snippet"]):
        return {"status": "uncertain", "confidence": 0.55,
                "evidence": f"行号漂移：邻近 ±5 行内能匹配，但 line {co_field['line']} 不匹配",
                "evidence_refs": refs + [
                    _ref_repo(co_field["file"], commit,
                              f"{max(1, s-5)}-{e+5}",
                              near.data["snippet"]),
                ]}

    # 用 grep 兜底
    grep = tools.grep_code(co.data["cwd"], co_field["file"], re.escape(co_field["code"].strip()))
    if grep.ok and grep.data["hits"]:
        first = grep.data["hits"][0]
        return {"status": "incorrect", "confidence": 0.85,
                "evidence": f"行号错误：实际匹配行 {first['line']}，标注 {co_field['line']}（{first['text'][:80]}）",
                "evidence_refs": refs + [
                    _ref_repo(co_field["file"], commit, first["line"], first["text"]),
                ]}

    return {"status": "incorrect", "confidence": 0.85,
            "evidence": f"代码片段不匹配：actual={actual[:80]} expected={expected[:80]}",
            "evidence_refs": refs}


def check_commit(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    advisory: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """commit 字段三态判定（I3 启动手册 §5 验收 2-3）。

    分层判定：
        Layer 1 - 格式：40 位小写 hex，否则 incorrect
        Layer 2 - 缓存可解析：tools.checkout 命中本地缓存，否则 incorrect
        Layer 3 - 与公告范围相容：仅当 advisory 提供可验证范围
                    （affected_versions / fixed_in）时执行，否则 fall-through 到
                    format+cache 通过即 correct；版本无法解析时 uncertain
        Role 区分（修复 vs 漏洞）：
        - role=fixed 必须满足 version >= fixed_in，否则 uncertain（防止把修复 commit 当成引入）
        - role=vulnerable 必须满足 version ∈ affected_versions，否则 uncertain
        - role=unknown 直接判 uncertain（无法判定语义角色）
    """
    commit = entry.get("commit", "")
    # ---- Layer 1: 格式 ----
    if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        return {"status": "incorrect", "confidence": 0.99,
                "evidence": f"commit 不是 40 位小写 hex：{commit!r}",
                "evidence_refs": []}

    project = normalize_project_from_repo(entry["repo_url"])
    # ---- Layer 2: 缓存可解析 ----
    co = tools.checkout(project, commit)
    if not co.ok:
        return {"status": "incorrect", "confidence": 0.90,
                "evidence": f"commit 在本地缓存中不可用：{co.error}",
                "evidence_refs": []}

    refs: List[Dict[str, str]] = [
        _ref_repo("<manifest>", commit, "0", f"commit {commit} exists in repo_cache"),
    ]
    gl = tools.git_log(project, commit, limit=1)
    if gl.ok and gl.data:
        first = gl.data[0]
        refs.append(_ref_git(project, commit, first["sha"], first.get("message", "")))

    # ---- Layer 3: 公告范围相容性 + role 区分 ----
    if advisory:
        affected = advisory.get("affected_versions") or []
        fixed_in = advisory.get("fixed_in")
        manifest_item = _lookup_manifest_item(tools, project, commit)
        role = manifest_item.get("role") if manifest_item else None
        project_version = manifest_item.get("version") if manifest_item else None

        if role == "unknown":
            return {
                "status": "uncertain", "confidence": 0.55,
                "evidence": (
                    f"manifest 标记 role=unknown，无法判定 commit {commit[:7]} 是漏洞版本还是修复版本"
                ),
                "evidence_refs": refs,
            }

        if role == "fixed" and fixed_in:
            meets = _version_meets_or_exceeds(project_version, fixed_in)
            if meets is False:
                return {
                    "status": "uncertain", "confidence": 0.70,
                    "evidence": (
                        f"manifest 标记 role=fixed 但项目版本 {project_version} < 公告 fixed_in {fixed_in}；"
                        f"无法确认 commit {commit[:7]} 是真正的修复 commit"
                    ),
                    "evidence_refs": refs,
                }
            if meets is True:
                return {
                    "status": "correct", "confidence": 0.92,
                    "evidence": (
                        f"commit {commit[:7]} 是修复版本（role=fixed, version={project_version} >= fixed_in={fixed_in}）"
                    ),
                    "evidence_refs": refs,
                }
            # meets is None：版本不可解析 → fall-through
        elif role == "vulnerable" and affected:
            in_range = _version_is_affected(project_version, affected)
            if in_range is False:
                return {
                    "status": "uncertain", "confidence": 0.70,
                    "evidence": (
                        f"manifest 标记 role=vulnerable 但项目版本 {project_version} 不在公告 "
                        f"affected_versions={affected} 范围内；无法确认 commit 是漏洞引入 commit"
                    ),
                    "evidence_refs": refs,
                }
            if in_range is True:
                return {
                    "status": "correct", "confidence": 0.92,
                    "evidence": (
                        f"commit {commit[:7]} 是漏洞引入版本（role=vulnerable, "
                        f"version={project_version} ∈ affected_versions）"
                    ),
                    "evidence_refs": refs,
                }
            # in_range is None：版本不可解析 → fall-through

    # 无 advisory 信息或 layer 3 无法判定 → 按格式+缓存通过算 correct
    return {"status": "correct", "confidence": 0.90,
            "evidence": f"commit {commit[:7]} 在本地缓存可用，且格式合规",
            "evidence_refs": refs}


def _lookup_manifest_item(
    tools: VulnGymTools, project: str, commit: str,
) -> Optional[Dict[str, Any]]:
    """从 tools.manifest 中按 (project, commit) 查找对应的 item。"""
    if not tools.manifest or not tools.manifest.get("items"):
        return None
    for it in tools.manifest["items"]:
        if it.get("project") == project and it.get("commit") == commit:
            return it
    return None


def check_vuln_ids(
    entry: Dict[str, Any],
    advisory: Dict[str, Any],
) -> Dict[str, Any]:
    ids = entry.get("vuln_ids", []) or []
    if not ids:
        return {"status": "uncertain", "confidence": 0.50,
                "evidence": "vuln_ids 为空，需要公告或人工补全",
                "evidence_refs": []}
    expected_cve = advisory.get("cve_id")
    expected_ghsa = advisory.get("ghsa_id")
    refs: List[Dict[str, str]] = []
    if expected_cve:
        refs.append(_ref_advisory("advisory.json#cve_id", expected_cve))
    if expected_ghsa:
        refs.append(_ref_advisory("advisory.json#ghsa_id", expected_ghsa))
    if expected_cve and expected_cve not in ids:
        return {"status": "incorrect", "confidence": 0.85,
                "evidence": f"vuln_ids 缺少公告中的 CVE：{expected_cve}",
                "evidence_refs": refs}
    if expected_ghsa and expected_ghsa not in ids:
        return {"status": "uncertain", "confidence": 0.55,
                "evidence": f"vuln_ids 缺少公告中的 GHSA：{expected_ghsa}",
                "evidence_refs": refs}
    return {"status": "correct", "confidence": 0.90,
            "evidence": f"vuln_ids={ids} 与公告一致",
            "evidence_refs": refs}


def check_vuln_title(
    entry: Dict[str, Any],
    advisory: Dict[str, Any],
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """vuln_title 语义判定。

    I4 契约：
      - 必须走 `parse_structured_response`，让 schema/confidence/脱敏/非空 evidence
        校验生效
      - LLM 失败（非法 JSON / 超时 / HTTP 错误）一律 semantic uncertain，
        禁止通过关键词启发式回退为 correct
      - 使用 prompts.VULN_TITLE_PROMPT（带 [PROMPT_VERSION=...] 前缀）走版本化模板
    """
    expected = advisory.get("title", "")
    actual = entry.get("vuln_title", "")
    refs: List[Dict[str, str]] = []
    if expected:
        refs.append(_ref_advisory("advisory.json#title", expected))
    if not expected:
        return {"status": "uncertain", "confidence": 0.50,
                "evidence": "公告标题缺失，触发 LLM 语义判断",
                "evidence_refs": refs}
    prompt = VULN_TITLE_PROMPT.format(expected=expected, actual=actual)
    out = llm.chat([LLMMessage("user", prompt)])
    data = parse_structured_response(out)
    # I4 兼容：append-merge 模式（LLM 返回的 evidence_refs 与 advisory refs 合并去重）
    data["evidence_refs"] = _merge_refs(data.get("evidence_refs") or [], refs)
    return data


def check_category(
    level: str,
    entry: Dict[str, Any],
    advisory: Dict[str, Any],
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """vuln_category_l1 / l2 语义判定。

    I4 契约：LLM 失败一律 uncertain；走 `parse_structured_response`；
    使用 prompts.vuln_category_prompt() 版本化模板。
    """
    actual = entry.get(f"vuln_category_{level}", "")
    expected = advisory.get(f"vuln_category_{level}_hint", "")
    refs: List[Dict[str, str]] = []
    if expected:
        refs.append(_ref_advisory(f"advisory.json#vuln_category_{level}_hint", expected))
    if not expected:
        return {"status": "uncertain", "confidence": 0.50,
                "evidence": f"公告未给出 l{level[-1]} 提示，需人工判定",
                "evidence_refs": refs}
    prompt = vuln_category_prompt(level, expected, actual)
    out = llm.chat([LLMMessage("user", prompt)])
    data = parse_structured_response(out)
    data["evidence_refs"] = _merge_refs(data.get("evidence_refs") or [], refs)
    return data


def check_trace(
    entry: Dict[str, Any],
    tools: VulnGymTools,
    llm: BaseLLMClient,
) -> Dict[str, Any]:
    """trace 校验：每节点文件/行号/代码片段是否存在，再让 LLM 判断整体合理性。"""
    trace = entry.get("trace", []) or []
    if not trace:
        return {"status": "uncertain", "confidence": 0.40,
                "evidence": "trace 为空（可能合理，但无法验证）",
                "evidence_refs": []}

    project = normalize_project_from_repo(entry["repo_url"])
    co = tools.checkout(project, entry["commit"])
    if not co.ok:
        return {"status": "incorrect", "confidence": 0.90,
                "evidence": f"trace 校验前置失败：{co.error}",
                "evidence_refs": []}

    bad_nodes = []
    refs: List[Dict[str, str]] = []
    for idx, node in enumerate(trace):
        reads = tools.read_file_lines(co.data["cwd"], node["file"],
                                      *_line_range(node["line"]))
        if not reads.ok:
            bad_nodes.append(f"#{idx} 文件不存在 {node['file']}")
            refs.append(_ref_repo(node["file"], entry["commit"], node["line"],
                                  f"file not found: {node['file']}"))
            continue
        actual = _norm_code(reads.data["snippet"])
        expected = _norm_code(node["code"])
        refs.append(_ref_repo(node["file"], entry["commit"], node["line"],
                              reads.data["snippet"]))
        if expected not in actual and actual not in expected:
            bad_nodes.append(f"#{idx} {node['file']}:{node['line']} 代码片段不匹配")

    if bad_nodes:
        return {"status": "incorrect", "confidence": 0.85,
                "evidence": "trace 节点异常：" + "; ".join(bad_nodes[:3]),
                "evidence_refs": refs}

    # 节点级都对，再让 LLM 判断"整体合理性"
    prompt = TRACE_OVERALL_PROMPT.format(
        entry_id=entry.get("entry_id", ""), node_count=len(trace),
    )
    out = llm.chat([LLMMessage("user", prompt)])
    data = parse_structured_response(out)
    data["evidence_refs"] = _merge_refs(data.get("evidence_refs") or [], refs)
    return data


# ============================================================
# 汇总：跑一条 entry 的全部字段（**逻辑不变**，ISSUE_OUTLINE §5 I3 明确禁止修改）
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
    # check_commit 接收 advisory 以启用 layer 3 (公告范围 + role) 判定（I3 启动手册 §5）
    fields["commit"] = check_commit(entry, tools, advisory=advisory) if advisory else check_commit(entry, tools)
    fields["vuln_ids"] = check_vuln_ids(entry, advisory) if advisory else {
        "status": "uncertain", "confidence": 0.40,
        "evidence": "公告缓存缺失，无法校验 vuln_ids",
        "evidence_refs": [],
    }
    fields["vuln_title"] = check_vuln_title(entry, advisory, llm) if advisory else {
        "status": "uncertain", "confidence": 0.40, "evidence": "公告缓存缺失",
        "evidence_refs": [],
    }
    fields["vuln_category_l1"] = check_category("l1", entry, advisory, llm) if advisory else {
        "status": "uncertain", "confidence": 0.40, "evidence": "公告缓存缺失",
        "evidence_refs": [],
    }
    fields["vuln_category_l2"] = check_category("l2", entry, advisory, llm) if advisory else {
        "status": "uncertain", "confidence": 0.40, "evidence": "公告缓存缺失",
        "evidence_refs": [],
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