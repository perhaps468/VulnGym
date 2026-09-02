# -*- coding: utf-8 -*-
"""I5 — Agent 规划、tool_trace、self-check 测试套件。

覆盖 I5 启动手册 §4 全部 7 个测试类、≥35 用例。

契约（来自 I5_START_HANDBOOK §3 与 I1 report_schema.json）：
  * plan 必含 version="1" / tools_planned / fields_planned
  * tool_trace ≥3 类工具调用（advisory + repository + git 各 ≥1）
  * tool_trace 失败也记录（ok=false + error），不抛未处理异常
  * tool_trace.input 脱敏（commit ≤12 字符、不含绝对路径）
  * self_check 必含 status/agree/comment/checked_fields 四键
  * self_check status=skipped|failed → agree 强制 false
  * verify_entry 返回 dict 必含 I1 schema 全部顶层字段
  * verify_entries 顺序处理 + 坏 entry 不中断
  * 完整 report 可被 schema.validate_report 校验通过
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vulngym-verify-demo"))

from vulngym_verify_demo import agent as agent_mod  # noqa: E402
from vulngym_verify_demo.agent import (  # noqa: E402
    EIGHT_FIELDS,
    get_eight_fields,
    get_tool_category,
    plan_for_entry,
    self_check,
    verify_entries,
    verify_entry,
)
from vulngym_verify_demo.llm_client import (  # noqa: E402
    BaseLLMClient,
    LLMMessage,
    SafeLLMClient,
    ScriptedMockLLMClient,
)
from vulngym_verify_demo.schema import (  # noqa: E402
    validate_plan,
    validate_report,
    validate_self_check,
    validate_tool_call,
)
from vulngym_verify_demo.tools import (  # noqa: E402
    ToolResult,
    VulnGymTools,
    load_manifest,
)

MOCK_REPO_ROOT = ROOT / "vulngym-verify-demo" / "mock_repo"
MOCK_ADV_DIR = ROOT / "vulngym-verify-demo" / "mock_advisories"


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture(scope="module")
def manifest() -> Dict[str, Any]:
    with open(MOCK_REPO_ROOT / "manifest.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def workspace(tmp_path: Path):
    """构造独立 repo_cache + advisory，复制 mock_repo + mock_advisories 内容。"""
    repo_cache = tmp_path / "repo_cache"
    advisory_dir = tmp_path / "advisories"
    repo_cache.mkdir()
    advisory_dir.mkdir()
    for src in MOCK_REPO_ROOT.rglob("*"):
        if src.is_file():
            rel = src.relative_to(MOCK_REPO_ROOT)
            dst = repo_cache / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())
    for src in MOCK_ADV_DIR.glob("*.json"):
        (advisory_dir / src.name).write_bytes(src.read_bytes())
    return repo_cache, advisory_dir


@pytest.fixture
def tools(workspace, manifest) -> VulnGymTools:
    repo_cache, advisory_dir = workspace
    return VulnGymTools(
        repo_cache_dir=repo_cache,
        advisory_dir=advisory_dir,
        manifest=manifest,
    )


@pytest.fixture
def llm() -> BaseLLMClient:
    return ScriptedMockLLMClient()


def _valid_entry() -> Dict[str, Any]:
    """构造一条最小合法 entry。"""
    return {
        "entry_id": "entry-00001",
        "report_id": "GHSA-DEMO-0001-XSS",
        "repo_url": "https://github.com/example/blog-platform",
        "commit": "1111111111111111111111111111111111111111",
        "verify": {
            "file": "src/handlers/comment.js",
            "commit": "1111111111111111111111111111111111111111",
        },
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "blog-platform",
        "source_link": "https://github.com/advisories/GHSA-DEMO-0001-XSS",
        "vuln_ids": ["CVE-2026-DEMO-0001", "GHSA-DEMO-0001-XSS"],
        "vuln_title": "Blog Platform Stored DOM XSS via Comment Rich Text",
        "vuln_category_l1": "XSS",
        "vuln_category_l2": "Stored XSS",
        "entry_point": {
            "file": "src/handlers/comment.js",
            "line": 97,
            "code": "insertTextHandler(data.content);",
        },
        "critical_operation": {
            "file": "src/lib/RichTextInput.svelte",
            "line": 348,
            "code": "tempDiv.innerHTML = htmlContent;",
        },
        "trace": [
            {
                "file": "src/lib/RichTextInput.svelte",
                "line": 343,
                "code": "renderRichText(content);",
            }
        ],
    }


# ============================================================
# TestPlan: plan_for_entry
# ============================================================


class TestPlan:
    """plan_for_entry 输出契约。"""

    def test_plan_version_is_string_one(self):
        plan = plan_for_entry(_valid_entry())
        assert plan["version"] == "1"
        assert isinstance(plan["version"], str)

    def test_plan_tools_covers_three_categories(self):
        plan = plan_for_entry(_valid_entry())
        cats = {get_tool_category(t) for t in plan["tools_planned"]}
        assert "advisory" in cats
        assert "repository" in cats
        assert "git" in cats

    def test_plan_fields_planned_has_eight_fields(self):
        plan = plan_for_entry(_valid_entry())
        assert set(plan["fields_planned"]) == set(EIGHT_FIELDS)
        assert len(plan["fields_planned"]) == 8

    def test_plan_round_trip_json(self):
        plan = plan_for_entry(_valid_entry())
        s = json.dumps(plan, ensure_ascii=False)
        loaded = json.loads(s)
        assert loaded == plan
        # schema 校验
        errs = validate_plan(loaded)
        assert errs == [], f"plan validate errors: {errs}"

    def test_plan_entry_id_report_id_propagated(self):
        entry = _valid_entry()
        plan = plan_for_entry(entry)
        assert plan["entry_id"] == entry["entry_id"]
        assert plan["report_id"] == entry["report_id"]

    def test_plan_with_minimal_entry(self):
        """空 entry 不抛异常。"""
        plan = plan_for_entry({})
        assert plan["version"] == "1"
        assert plan["entry_id"] is None
        assert plan["report_id"] is None


# ============================================================
# TestToolTrace: _build_tool_trace / tool_trace schema
# ============================================================


class TestToolTrace:
    """tool_trace 构造与 schema 契约。"""

    def test_three_categories_present(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        cats = {get_tool_category(t["tool"]) for t in rep["tool_trace"]}
        assert "advisory" in cats
        assert "repository" in cats
        assert "git" in cats

    def test_seq_strictly_monotonic(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        seqs = [t["seq"] for t in rep["tool_trace"]]
        assert seqs == sorted(seqs)
        assert all(isinstance(s, int) for s in seqs)
        assert all(s >= 1 for s in seqs)

    def test_ok_false_recorded_on_failure(self, tools):
        """advisory 找不到时仍记录（ok=false + error）。"""
        entry = _valid_entry()
        entry["report_id"] = "GHSA-NOT-EXIST-XYZ"
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        adv = next(t for t in rep["tool_trace"] if t["tool"] == "read_advisory")
        assert adv["ok"] is False
        assert isinstance(adv["error"], str) and adv["error"]

    def test_input_redacted_for_commit(self, tools):
        """commit 在 trace.input 中只出现前 12 字符（防 32+ hex 触发 redact）。"""
        entry = _valid_entry()
        full_commit = "1111111111111111111111111111111111111111"
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        # 把所有 input 序列化成字符串后校验
        all_input_str = json.dumps([t["input"] for t in rep["tool_trace"]], ensure_ascii=False)
        assert full_commit not in all_input_str
        # 但 commit 前 12 字符应出现
        assert "111111111111" in all_input_str

    def test_input_no_absolute_path(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        all_input_str = json.dumps([t["input"] for t in rep["tool_trace"]], ensure_ascii=False)
        # 不能出现 Windows / POSIX 绝对路径
        assert "C:\\" not in all_input_str
        assert "C:/" not in all_input_str
        assert not any(seg in all_input_str for seg in ["/home/", "/Users/", "/tmp/", "/var/"])

    def test_no_unhandled_exception_on_bad_commit(self, tools):
        """坏 commit 仍生成报告，不抛异常。"""
        entry = _valid_entry()
        entry["commit"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"  # 不在缓存
        entry["verify"]["commit"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        assert isinstance(rep, dict)
        assert "tool_trace" in rep
        # 仍然 3 类工具都被记录
        cats = {get_tool_category(t["tool"]) for t in rep["tool_trace"]}
        assert "advisory" in cats
        assert "repository" in cats
        assert "git" in cats

    def test_evidence_refs_are_json_paths(self, tools):
        """trace.evidence_refs 必须是 JSON 路径格式 (fields.<name>.evidence)。"""
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        for t in rep["tool_trace"]:
            for ref in t["evidence_refs"]:
                assert isinstance(ref, str)
                assert ref.startswith("fields.")
                assert ".evidence" in ref

    def test_all_tool_calls_have_ok_field(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        for t in rep["tool_trace"]:
            assert "ok" in t
            assert isinstance(t["ok"], bool)
            # schema 校验通过
            errs = validate_tool_call(t)
            assert errs == [], f"validate_tool_call errors: {errs}"


# ============================================================
# TestSelfCheck: self_check 函数契约
# ============================================================


class TestSelfCheck:
    """self_check 四键契约与 skipped/failed→agree=false 约束。"""

    def test_completed_path_agree_from_llm(self):
        """LLM 返回 agree=True → status=completed + agree=True。"""
        llm = ScriptedMockLLMClient()  # self-check 分支默认返回 agree=True
        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, llm)
        assert out["status"] == "completed"
        assert out["agree"] is True
        assert isinstance(out["comment"], str) and out["comment"]
        assert isinstance(out["checked_fields"], list)

    def test_skipped_path_agree_is_false(self):
        """LLM 抛异常 → status=skipped + agree=False（I5 契约）。"""
        class BoomLLM(BaseLLMClient):
            name = "BoomLLM"
            def chat(self, messages, *, temperature=0.0):
                raise RuntimeError("network down")

        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, BoomLLM())
        assert out["status"] == "skipped"
        assert out["agree"] is False
        assert isinstance(out["comment"], str) and out["comment"]

    def test_skipped_path_safe_client(self):
        """SafeLLMClient 的 self-check 分支返回 False → status=completed（来自 LLM），agree=False。"""
        # SafeLLMClient 的 self-check 分支返回 agree=False + comment
        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, SafeLLMClient())
        # SafeLLMClient 返回有效 dict → completed 路径
        assert out["status"] == "completed"
        assert out["agree"] is False
        assert out["comment"]

    def test_checked_fields_lists_all_fields(self):
        llm = ScriptedMockLLMClient()
        fr = {k: {"status": "correct", "confidence": 0.9, "evidence": "x",
                  "evidence_refs": []} for k in EIGHT_FIELDS}
        out = self_check(_valid_entry(), fr, llm)
        assert set(out["checked_fields"]) == set(EIGHT_FIELDS)

    def test_comment_never_empty(self):
        """comment 必须非空（I1 schema 隐式）。"""
        class EmptyCommentLLM(BaseLLMClient):
            name = "EmptyCommentLLM"
            def chat(self, messages, *, temperature=0.0):
                return json.dumps({"agree": True, "comment": "   "})

        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, EmptyCommentLLM())
        assert out["comment"]  # 非空
        # 若 LLM 返回空白 comment，应替换为默认
        assert out["comment"].strip()

    def test_illegal_json_returns_skipped(self):
        """LLM 返回非法 JSON → status=skipped + agree=False。"""
        class BadJSONLLM(BaseLLMClient):
            name = "BadJSONLLM"
            def chat(self, messages, *, temperature=0.0):
                return "not a json at all"

        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, BadJSONLLM())
        assert out["status"] == "skipped"
        assert out["agree"] is False

    def test_non_dict_json_returns_skipped(self):
        """LLM 返回合法 JSON 但不是 dict → skipped + agree=False。"""
        class NonDictLLM(BaseLLMClient):
            name = "NonDictLLM"
            def chat(self, messages, *, temperature=0.0):
                return json.dumps([1, 2, 3])

        fr = {"entry_point": {"status": "correct", "confidence": 0.9, "evidence": "x",
                              "evidence_refs": []}}
        out = self_check(_valid_entry(), fr, NonDictLLM())
        assert out["status"] == "skipped"
        assert out["agree"] is False

    def test_self_check_schema_validate(self):
        """self_check 返回值必须通过 validate_self_check。"""
        llm = ScriptedMockLLMClient()
        fr = {k: {"status": "correct", "confidence": 0.9, "evidence": "x",
                  "evidence_refs": []} for k in EIGHT_FIELDS}
        out = self_check(_valid_entry(), fr, llm)
        errs = validate_self_check(out)
        assert errs == [], f"validate_self_check errors: {errs}"


# ============================================================
# TestVerifyEntry: verify_entry 完整流程
# ============================================================


class TestVerifyEntry:
    """verify_entry 端到端契约。"""

    def test_returns_all_required_top_fields(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        for key in (
            "report_id", "entry_id", "verdict", "fields",
            "summary", "self_check", "plan", "tool_trace",
        ):
            assert key in rep, f"missing top-level key: {key}"

    def test_tool_trace_has_three_categories(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        cats = {get_tool_category(t["tool"]) for t in rep["tool_trace"]}
        assert {"advisory", "repository", "git"}.issubset(cats)

    def test_verdict_is_three_state_value(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert rep["verdict"] in ("correct", "incorrect", "uncertain")

    def test_summary_non_empty(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert isinstance(rep["summary"], str)
        assert rep["summary"].strip()

    def test_bad_commit_still_generates_report(self, tools, llm):
        entry = _valid_entry()
        entry["commit"] = "0" * 40  # 不在 manifest 中
        entry["verify"]["commit"] = "0" * 40
        rep = verify_entry(entry, tools, llm)
        assert isinstance(rep, dict)
        assert "fields" in rep
        assert len(rep["fields"]) == 8

    def test_missing_report_id_still_generates_report(self, tools, llm):
        entry = _valid_entry()
        entry["report_id"] = ""
        rep = verify_entry(entry, tools, llm)
        assert isinstance(rep, dict)
        assert rep["report_id"] == ""
        # tool_trace 的 read_advisory 记录应当 ok=false
        adv = next(t for t in rep["tool_trace"] if t["tool"] == "read_advisory")
        assert adv["ok"] is False

    def test_self_check_has_four_keys(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        sc = rep["self_check"]
        for key in ("status", "agree", "comment", "checked_fields"):
            assert key in sc, f"self_check missing key: {key}"

    def test_plan_version_equals_one(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert rep["plan"]["version"] == "1"


# ============================================================
# TestVerifyEntries: 批量处理
# ============================================================


class TestVerifyEntries:
    """verify_entries 顺序处理 + 鲁棒性。"""

    def test_empty_list_returns_empty(self, tools, llm):
        out = verify_entries([], tools, llm)
        assert out == []

    def test_processes_in_order(self, tools, llm):
        e1 = _valid_entry()
        e2 = _valid_entry()
        e2["entry_id"] = "entry-00002"
        e2["report_id"] = "GHSA-DEMO-0002-RCE"
        e2["repo_url"] = "https://github.com/example/shell-runner"
        e2["commit"] = "2222222222222222222222222222222222222222"
        e2["verify"]["commit"] = "2222222222222222222222222222222222222222"
        e2["verify"]["file"] = "src/api.js"
        e2["entry_point"]["file"] = "src/api.js"
        e2["entry_point"]["code"] = 'spawn("sh", ["-c", cmd]);'
        e2["critical_operation"]["file"] = "src/runner.js"
        e2["critical_operation"]["code"] = "child_process.exec(userInput);"
        e2["trace"] = []
        e2["vuln_ids"] = ["CVE-2026-DEMO-0002"]
        e2["vuln_title"] = "Shell Runner RCE"
        e2["vuln_category_l1"] = "代码注入"
        e2["vuln_category_l2"] = "命令注入"

        out = verify_entries([e1, e2], tools, llm)
        assert len(out) == 2
        assert out[0]["entry_id"] == "entry-00001"
        assert out[1]["entry_id"] == "entry-00002"

    def test_mixed_valid_and_bad_does_not_break(self, tools, llm):
        good = _valid_entry()
        bad = _valid_entry()
        bad["commit"] = "X" * 40  # 坏 commit
        bad["verify"]["commit"] = "X" * 40
        out = verify_entries([good, bad], tools, llm)
        assert len(out) == 2
        # 两条都返回 dict
        assert all(isinstance(r, dict) for r in out)
        assert all("fields" in r and len(r["fields"]) == 8 for r in out)

    def test_verbose_does_not_raise(self, tools, llm, capsys):
        out = verify_entries([_valid_entry()], tools, llm, verbose=True)
        assert len(out) == 1
        # 输出捕获存在（verbose 模式打了字）
        captured = capsys.readouterr()
        assert "[plan]" in captured.out or "[verdict]" in captured.out


# ============================================================
# TestSchemaConformance: 整报告通过 I1 schema 校验
# ============================================================


class TestSchemaConformance:
    """完整 VerificationReport 必须通过 validate_report。"""

    def test_full_report_validates(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        errs = validate_report(rep)
        assert errs == [], f"validate_report errors: {errs}"

    def test_plan_version_strict_one(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert rep["plan"]["version"] == "1"

    def test_self_check_agree_false_when_skipped(self):
        class BoomLLM(BaseLLMClient):
            name = "BoomLLM"
            def chat(self, messages, *, temperature=0.0):
                raise RuntimeError("net down")
        fr = {k: {"status": "correct", "confidence": 0.9, "evidence": "x",
                  "evidence_refs": []} for k in EIGHT_FIELDS}
        out = self_check(_valid_entry(), fr, BoomLLM())
        assert out["status"] == "skipped"
        assert out["agree"] is False

    def test_tool_trace_seq_at_least_one(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert len(rep["tool_trace"]) >= 1
        for t in rep["tool_trace"]:
            assert t["seq"] >= 1

    def test_eight_fields_present(self, tools, llm):
        rep = verify_entry(_valid_entry(), tools, llm)
        assert set(rep["fields"].keys()) == set(EIGHT_FIELDS)


# ============================================================
# TestRedaction: trace.input 脱敏规则
# ============================================================


class TestRedaction:
    """trace.input 必须脱敏：commit ≤12 字符 + 无绝对路径。"""

    def test_commit_truncated(self, tools):
        entry = _valid_entry()
        long_commit = "abcdef0123456789abcdef0123456789abcdef01"  # 40 chars
        entry["commit"] = long_commit
        entry["verify"]["commit"] = long_commit
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        all_input = json.dumps([t["input"] for t in rep["tool_trace"]], ensure_ascii=False)
        # 完整 40-char commit 不应出现
        assert long_commit not in all_input
        # 前 12 字符 + ellipsis 应出现
        assert "abcdef012345" in all_input

    def test_no_absolute_path_in_trace(self, tools):
        entry = _valid_entry()
        rep = verify_entry(entry, tools, ScriptedMockLLMClient())
        all_input = json.dumps([t["input"] for t in rep["tool_trace"]], ensure_ascii=False)
        # 不包含 Windows 绝对路径特征
        assert not any(s in all_input for s in ("C:\\", "D:\\", "/home/", "/Users/", "/tmp/"))


# ============================================================
# TestHelpers: 辅助函数
# ============================================================


class TestHelpers:
    """暴露给上层的 helper 函数。"""

    def test_get_eight_fields_returns_copy(self):
        f1 = get_eight_fields()
        f1.append("extra")
        f2 = get_eight_fields()
        assert "extra" not in f2
        assert len(f2) == 8

    def test_get_tool_category_known(self):
        assert get_tool_category("read_advisory") == "advisory"
        assert get_tool_category("checkout") == "git"
        assert get_tool_category("read_file_lines") == "repository"
        assert get_tool_category("git_log") == "git"
        assert get_tool_category("grep_code") == "repository"

    def test_get_tool_category_unknown(self):
        assert get_tool_category("nope") is None


# ============================================================
# TestImportSurface: 公共符号导出
# ============================================================


class TestImportSurface:
    """I5 公共符号可从 agent 模块导入。"""

    def test_public_functions_importable(self):
        from vulngym_verify_demo.agent import (  # noqa: F401
            plan_for_entry,
            self_check,
            verify_entry,
            verify_entries,
            get_eight_fields,
            get_tool_category,
            EIGHT_FIELDS,
        )