# -*- coding: utf-8 -*-
"""Prompt 版本化中心（I4 新增）。

每个语义字段的 prompt 模板及其版本号；每次 `llm.chat` 调用前都会把
``[PROMPT_VERSION=<key>@<version>]`` 前缀注入到 user prompt，便于审计与
回放（I4 启动手册 §3.3）。
"""
from __future__ import annotations

from typing import Any, Dict


# ============================================================
# Prompt 版本号
# ============================================================

PROMPT_VERSIONS: Dict[str, str] = {
    "vuln_title_judge": "1",
    "vuln_category_l1_judge": "1",
    "vuln_category_l2_judge": "1",
    "vuln_ids_judge": "1",
    "trace_overall_judge": "1",
    "self_check_judge": "1",
}


def get_prompt_version(key: str) -> str:
    """获取 prompt 版本号；未知 key 返回 'unknown'。"""
    return PROMPT_VERSIONS.get(key, "unknown")


# ============================================================
# Prompt 模板（含 [PROMPT_VERSION=...] 前缀）
# ============================================================

def _with_version(key: str, body: str) -> str:
    """在 prompt 开头插入版本前缀。"""
    return f"[PROMPT_VERSION={key}@{get_prompt_version(key)}]\n{body}"


# ---- vuln_title ----
VULN_TITLE_PROMPT = _with_version(
    "vuln_title_judge",
    (
        "判断 vuln_title 是否正确。\n"
        "advisory title: {expected}\n"
        "actual: {actual}\n"
        "返回 JSON：{{status,confidence,evidence}}"
    ),
)


# ---- vuln_category ----
def vuln_category_prompt(level: str, expected: str, actual: str) -> str:
    return _with_version(
        f"vuln_category_{level}_judge",
        (
            f"判断 vuln_category_{level} 是否正确。\n"
            f"advisory_hint_l{level[-1]}: {expected}\n"
            f"actual: {actual}\n"
            f"返回 JSON：{{status,confidence,evidence}}"
        ),
    )


# ---- vuln_ids ----
VULN_IDS_PROMPT = _with_version(
    "vuln_ids_judge",
    (
        "判断 vuln_ids 列表是否与公告一致。\n"
        "advisory cve_id: {cve}\n"
        "advisory ghsa_id: {ghsa}\n"
        "actual vuln_ids: {actual}\n"
        "返回 JSON：{{status,confidence,evidence}}"
    ),
)


# ---- trace overall ----
TRACE_OVERALL_PROMPT = _with_version(
    "trace_overall_judge",
    (
        "trace 链路整体合理性判断。\n"
        "entry_id: {entry_id}\n"
        "trace 节点数: {node_count}\n"
        "返回 JSON：{{status,confidence,evidence}}"
    ),
)


# ---- self-check ----
SELF_CHECK_PROMPT = _with_version(
    "self_check_judge",
    (
        "请复核以下 8 个字段判定，输出自检结论。\n"
        "fields dump:\n{fields_dump}\n"
        "返回 JSON：{{agree: bool, comment: str}}"
    ),
)
