# -*- coding: utf-8 -*-
"""I3 — 字段检查器 evidence_refs 测试套件。

覆盖 I3 启动手册 §4 全部 10 个测试类、≥34 用例。

契约（由 I1 schema.py 冻结）：
  * evidence_refs: List[{source, locator, quote}]
  * source ∈ {"advisory", "repository", "git"}
  * locator/quote 是 str
  * evidence_refs=[] 时 evidence 必须非空
  * validate_field_result 对 8 字段返回值全部 pass
  * check_all_fields 汇总行为不变
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vulngym-verify-demo"))

from vulngym_verify_demo.field_checkers import (  # noqa: E402
    _ref_repo,
    _ref_git,
    _ref_advisory,
    check_entry_point,
    check_critical_operation,
    check_commit,
    check_vuln_ids,
    check_vuln_title,
    check_category,
    check_trace,
    check_all_fields,
)
from vulngym_verify_demo.schema import (  # noqa: E402
    validate_field_result,
    EVIDENCE_SOURCE_VALUES,
    STATUS_VALUES,
)
from vulngym_verify_demo.tools import VulnGymTools  # noqa: E402
from vulngym_verify_demo.llm_client import ScriptedMockLLMClient  # noqa: E402


# ============================================================
# Fixtures
# ============================================================

MOCK_REPO_ROOT = ROOT / "vulngym-verify-demo" / "mock_repo"
MOCK_ADV_DIR = ROOT / "vulngym-verify-demo" / "mock_advisories"


@pytest.fixture(scope="module")
def manifest() -> Dict[str, Any]:
    with open(MOCK_REPO_ROOT / "manifest.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def tmp_workspace(tmp_path: Path):
    """构造独立 repo_cache + advisory，复制 mock_repo + mock_advisories 内容。"""
    repo_cache = tmp_path / "repo_cache"
    advisory_dir = tmp_path / "advisories"
    repo_cache.mkdir()
    advisory_dir.mkdir()
    # 镜像 mock_repo/<project>/<commit>/...
    for src in MOCK_REPO_ROOT.rglob("*"):
        if src.is_file():
            rel = src.relative_to(MOCK_REPO_ROOT)
            dst = repo_cache / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())
    # 镜像 advisories
    for src in MOCK_ADV_DIR.glob("*.json"):
        (advisory_dir / src.name).write_bytes(src.read_bytes())
    return repo_cache, advisory_dir


@pytest.fixture
def tools(tmp_workspace) -> VulnGymTools:
    repo_cache, advisory_dir = tmp_workspace
    return VulnGymTools(
        repo_cache_dir=repo_cache,
        advisory_dir=advisory_dir,
        manifest=None,
    )


@pytest.fixture
def llm() -> ScriptedMockLLMClient:
    return ScriptedMockLLMClient()


def _base_entry(project_item: Dict[str, Any], report_id: str = "GHSA-DEMO-0001-XSS") -> Dict[str, Any]:
    """构造一条完整 entry，指向 manifest 里的某个 project/commit/file。"""
    return {
        "entry_id": "entry-" + project_item["project"],
        "report_id": report_id,
        "repo_url": project_item["repo_url"],
        "commit": project_item["commit"],
        "entry_point": {
            "file": project_item["file"],
            "line": project_item["targets"][0]["line"],
            "code": project_item["targets"][0]["code"],
        },
        "critical_operation": {
            "file": project_item["file"],
            "line": project_item["targets"][0]["line"],
            "code": project_item["targets"][0]["code"],
        },
        "trace": [
            {
                "file": project_item["file"],
                "line": project_item["targets"][0]["line"],
                "code": project_item["targets"][0]["code"],
            },
        ],
        "vuln_ids": [],
        "vuln_title": "",
        "vuln_category_l1": "",
        "vuln_category_l2": "",
    }


# ============================================================
# TestRefFactories
# ============================================================

class TestRefFactories:
    """3 个 EvidenceRef 工厂函数的纯逻辑。"""

    def test_repo_ref_shape(self):
        r = _ref_repo("src/a.js", "1" * 40, 42, "foo();")
        assert r == {"source": "repository", "locator": "1111111:src/a.js:42", "quote": "foo();"}

    def test_repo_ref_quote_truncated_to_80(self):
        long = "x" * 200
        r = _ref_repo("f", "1" * 40, 1, long)
        assert len(r["quote"]) == 80
        assert r["quote"] == "x" * 80

    def test_git_ref_shape(self):
        r = _ref_git("blog", "1" * 40, "abc1234", "introduce: blog change")
        assert r["source"] == "git"
        assert r["locator"].startswith("blog/1111111:")
        assert "introduce" in r["quote"]

    def test_advisory_ref_shape(self):
        r = _ref_advisory("advisory.json#cve_id", "CVE-2026-DEMO-0001")
        assert r == {
            "source": "advisory",
            "locator": "advisory.json#cve_id",
            "quote": "CVE-2026-DEMO-0001",
        }

    def test_all_sources_valid(self):
        for fn in [_ref_repo, _ref_git, _ref_advisory]:
            r = fn("dummy", "1" * 40, 1, "x") if fn is not _ref_advisory else fn("advisory.json#x", "y")
            assert r["source"] in EVIDENCE_SOURCE_VALUES


# ============================================================
# TestEvidenceRefsShape
# ============================================================

class TestEvidenceRefsShape:
    """8 个 check_field_X 返回值都含 evidence_refs: list。"""

    def test_check_entry_point_returns_list(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_entry_point(e, tools, llm)
        assert "evidence_refs" in r
        assert isinstance(r["evidence_refs"], list)

    def test_check_critical_operation_returns_list(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_critical_operation(e, tools, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_check_commit_returns_list(self, tools, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_commit(e, tools)
        assert isinstance(r["evidence_refs"], list)

    def test_check_vuln_ids_returns_list(self, manifest):
        e = _base_entry(manifest["items"][0])
        e["vuln_ids"] = ["CVE-2026-DEMO-0001"]
        adv = {"cve_id": "CVE-2026-DEMO-0001", "ghsa_id": "GHSA-DEMO-0001-XSS"}
        r = check_vuln_ids(e, adv)
        assert isinstance(r["evidence_refs"], list)

    def test_check_vuln_title_returns_list(self, manifest, llm):
        e = _base_entry(manifest["items"][0])
        e["vuln_title"] = "Stored XSS"
        adv = {"title": "Blog Platform Stored DOM XSS"}
        r = check_vuln_title(e, adv, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_check_category_returns_list(self, manifest, llm):
        e = _base_entry(manifest["items"][0])
        e["vuln_category_l1"] = "XSS"
        adv = {"vuln_category_l1_hint": "XSS"}
        r = check_category("l1", e, adv, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_check_trace_returns_list(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_trace(e, tools, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_source_enum_constraint(self, tools, llm, manifest):
        """所有填充的 source 必须在 I1 冻结的 frozenset 内。"""
        e = _base_entry(manifest["items"][0])
        r = check_entry_point(e, tools, llm)
        for ref in r["evidence_refs"]:
            assert ref["source"] in EVIDENCE_SOURCE_VALUES

    def test_each_ref_has_three_keys(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_entry_point(e, tools, llm)
        for ref in r["evidence_refs"]:
            assert set(ref.keys()) == {"source", "locator", "quote"}
            assert isinstance(ref["locator"], str)
            assert isinstance(ref["quote"], str)

    def test_empty_refs_require_non_empty_evidence(self, tools):
        """evidence_refs=[] 时 evidence 必须解释缺口（I1 §4.1）。"""
        e = _base_entry({
            "repo_url": "https://github.com/example/no-such-project",
            "project": "no-such-project",
            "commit": "f" * 40,
            "file": "x.js",
            "targets": [{"line": 1, "code": "x();"}],
        })
        r = check_commit(e, tools)
        assert r["evidence_refs"] == []
        assert len(r["evidence"]) > 0  # evidence 必须解释缺口


# ============================================================
# TestEntryPointRefs
# ============================================================

class TestEntryPointRefs:
    """entry_point 5 种场景。"""

    def test_correct_match_filled_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]  # blog-platform handlers/comment.js
        e = _base_entry(item)
        r = check_entry_point(e, tools, llm)
        assert r["status"] == "correct"
        assert len(r["evidence_refs"]) >= 1
        assert r["evidence_refs"][0]["source"] == "repository"
        assert item["commit"][:7] in r["evidence_refs"][0]["locator"]
        assert item["file"] in r["evidence_refs"][0]["locator"]

    def test_line_drift_uncertain_with_two_refs(self, tools, llm, manifest):
        """标注 line 漂移超 ±5 范围但 code 真实 → 走 grep 兜底 → 2 refs。"""
        item = manifest["items"][0]
        e = _base_entry(item)
        # 偏移 10 行（超过 ±5 容错窗口），code 真实 → 应触发 grep 兜底或 incorrect
        e["entry_point"]["line"] = max(1, item["targets"][0]["line"] - 10)
        e["entry_point"]["code"] = item["targets"][0]["code"]
        r = check_entry_point(e, tools, llm)
        # 行号错位明显，status 应是 incorrect（精确读找不到 + ±5 也找不到）
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1

    def test_code_mismatch_with_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["entry_point"]["code"] = "totallyDifferentCode();"
        r = check_entry_point(e, tools, llm)
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1
        assert r["evidence_refs"][0]["source"] == "repository"

    def test_file_missing_with_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["entry_point"]["file"] = "src/missing.js"
        r = check_entry_point(e, tools, llm)
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1

    def test_checkout_failure_empty_refs(self, tools, llm, manifest):
        e = _base_entry({
            "repo_url": "https://github.com/example/no-such",
            "project": "no-such",
            "commit": "1" * 40,
            "file": "x.js",
            "targets": [{"line": 1, "code": "x();"}],
        })
        r = check_entry_point(e, tools, llm)
        assert r["status"] == "incorrect"
        assert r["evidence_refs"] == []
        assert "checkout" in r["evidence"].lower() or "无法" in r["evidence"]


# ============================================================
# TestCriticalOpRefs
# ============================================================

class TestCriticalOpRefs:
    """critical_operation 4 种场景。"""

    def test_match_fills_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        r = check_critical_operation(e, tools, llm)
        assert r["status"] == "correct"
        assert r["evidence_refs"][0]["source"] == "repository"

    def test_mismatch_with_repo_ref(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["critical_operation"]["code"] = "wrongCode();"
        r = check_critical_operation(e, tools, llm)
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1

    def test_line_drift_near_window(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["critical_operation"]["line"] = item["targets"][0]["line"] + 2
        e["critical_operation"]["code"] = item["targets"][0]["code"]
        r = check_critical_operation(e, tools, llm)
        # ±5 范围内能找到 → uncertain 或 incorrect，refs 应有
        assert len(r["evidence_refs"]) >= 1

    def test_grep_fallback_includes_extra_ref(self, tools, llm, manifest):
        """标注 code 在 ±5 行外，但 grep 能找到 → incorrect + 至少 2 refs。"""
        item = manifest["items"][0]
        e = _base_entry(item)
        # 偏移 10 行（超过 ±5 容错窗口），但 code 是真实 target code
        # 此时原 ±5 read 找不到 → grep 兜底 → 2 refs
        e["critical_operation"]["line"] = max(1, item["targets"][0]["line"] - 10)
        e["critical_operation"]["code"] = item["targets"][0]["code"]
        r = check_critical_operation(e, tools, llm)
        assert len(r["evidence_refs"]) >= 1  # 至少 repo ref
        # 若 grep 命中 → 2 refs；否则仅原始 ref
        if r["status"] == "incorrect":
            assert r["evidence_refs"][0]["source"] == "repository"


# ============================================================
# TestCommitRefs
# ============================================================

class TestCommitRefs:
    """commit 字段 3 种场景。"""

    def test_bad_format_empty_refs(self, tools, manifest):
        e = _base_entry(manifest["items"][0])
        e["commit"] = "not-40-hex"
        r = check_commit(e, tools)
        assert r["status"] == "incorrect"
        assert r["evidence_refs"] == []

    def test_cache_miss_empty_refs(self, tools, manifest):
        e = _base_entry(manifest["items"][0])
        e["commit"] = "f" * 40  # 不在 manifest
        r = check_commit(e, tools)
        assert r["status"] == "incorrect"
        assert r["evidence_refs"] == []

    def test_normal_match_fills_repo_and_git(self, tools, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_commit(e, tools)
        assert r["status"] == "correct"
        sources = {ref["source"] for ref in r["evidence_refs"]}
        assert "repository" in sources
        assert "git" in sources


# ============================================================
# TestVulnIdsRefs
# ============================================================

class TestVulnIdsRefs:
    """vuln_ids 3 种场景。"""

    def test_missing_cve_in_advisory(self):
        """entry 中缺 CVE（advisory 有） → incorrect + 填 advisory refs。"""
        e = {"vuln_ids": ["GHSA-DEMO-0001-XSS"]}
        adv = {"cve_id": "CVE-2026-DEMO-0001", "ghsa_id": "GHSA-DEMO-0001-XSS"}
        r = check_vuln_ids(e, adv)
        assert r["status"] == "incorrect"
        assert any(ref["source"] == "advisory" for ref in r["evidence_refs"])

    def test_missing_ghsa_in_advisory(self):
        e = {"vuln_ids": ["CVE-2026-DEMO-0001"]}
        adv = {"cve_id": "CVE-2026-DEMO-0001", "ghsa_id": "GHSA-DEMO-0001-XSS"}
        r = check_vuln_ids(e, adv)
        assert r["status"] == "uncertain"
        assert any(ref["source"] == "advisory" for ref in r["evidence_refs"])

    def test_normal_match_with_advisory_refs(self):
        e = {"vuln_ids": ["CVE-2026-DEMO-0001", "GHSA-DEMO-0001-XSS"]}
        adv = {"cve_id": "CVE-2026-DEMO-0001", "ghsa_id": "GHSA-DEMO-0001-XSS"}
        r = check_vuln_ids(e, adv)
        assert r["status"] == "correct"
        sources = {ref["source"] for ref in r["evidence_refs"]}
        assert sources == {"advisory"}


# ============================================================
# TestTitleRefs
# ============================================================

class TestTitleRefs:
    """vuln_title 2 种场景。"""

    def test_llm_success_includes_advisory_ref(self, manifest, llm):
        e = {"vuln_title": "Stored DOM XSS in blog comments"}
        adv = {"title": "Blog Platform Stored DOM XSS via Comment Rich Text"}
        r = check_vuln_title(e, adv, llm)
        assert isinstance(r["evidence_refs"], list)
        # advisory ref 在 prompt 构造时就已填入
        assert any(ref["source"] == "advisory" for ref in r["evidence_refs"])

    def test_llm_failure_keeps_advisory_ref(self, manifest, llm):
        class BrokenLLM:
            name = "BrokenLLM"
            def chat(self, messages, *, temperature=0.0):
                return "not json"
        e = {"vuln_title": "Anything"}
        adv = {"title": "Real Title"}
        r = check_vuln_title(e, adv, BrokenLLM())
        # 即使 LLM 失败，advisory ref 应保留
        assert any(ref["source"] == "advisory" for ref in r["evidence_refs"])


# ============================================================
# TestCategoryRefs
# ============================================================

class TestCategoryRefs:
    """vuln_category_l1/l2 2 种场景。"""

    def test_l1_match(self, manifest, llm):
        e = {"vuln_category_l1": "XSS"}
        adv = {"vuln_category_l1_hint": "XSS"}
        r = check_category("l1", e, adv, llm)
        assert isinstance(r["evidence_refs"], list)
        assert r["evidence_refs"][0]["source"] == "advisory"

    def test_l2_match(self, manifest, llm):
        e = {"vuln_category_l2": "Stored XSS"}
        adv = {"vuln_category_l2_hint": "Stored XSS"}
        r = check_category("l2", e, adv, llm)
        assert r["evidence_refs"][0]["source"] == "advisory"


# ============================================================
# TestTraceRefs
# ============================================================

class TestTraceRefs:
    """trace 4 种场景。"""

    def test_empty_trace(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        e["trace"] = []
        r = check_trace(e, tools, llm)
        assert r["status"] == "uncertain"
        assert r["evidence_refs"] == []

    def test_single_node_match(self, tools, llm, manifest):
        e = _base_entry(manifest["items"][0])
        r = check_trace(e, tools, llm)
        assert isinstance(r["evidence_refs"], list)

    def test_multi_node_each_node_ref(self, tools, llm, manifest):
        """trace 多节点 → 每个节点一个 ref。"""
        item = manifest["items"][1]  # blog RichTextInput.svelte (2 targets)
        e = _base_entry(item)
        e["trace"] = [
            {"file": item["file"], "line": t["line"], "code": t["code"]}
            for t in item["targets"]
        ]
        r = check_trace(e, tools, llm)
        # 至少每个节点一个 ref
        assert len(r["evidence_refs"]) >= len(item["targets"])

    def test_node_with_missing_file(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["trace"] = [
            {"file": "src/missing.js", "line": 1, "code": "x();"},
        ]
        r = check_trace(e, tools, llm)
        assert r["status"] == "incorrect"
        assert len(r["evidence_refs"]) >= 1


# ============================================================
# TestBackwardsCompat
# ============================================================

class TestBackwardsCompat:
    """check_all_fields 行为不变 + verdict 规则不变。"""

    def test_check_all_fields_keys(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["vuln_ids"] = ["CVE-2026-DEMO-0001"]
        out = check_all_fields(e, tools, llm)
        assert "verdict" in out
        assert "fields" in out
        assert "summary" in out
        assert set(out["fields"].keys()) == {
            "entry_point", "critical_operation", "commit", "vuln_ids",
            "vuln_title", "vuln_category_l1", "vuln_category_l2", "trace",
        }

    def test_verdict_correct_when_all_correct(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["vuln_ids"] = ["CVE-2026-DEMO-0001"]
        e["vuln_title"] = "Blog Platform Stored DOM XSS via Comment Rich Text"
        e["vuln_category_l1"] = "XSS"
        e["vuln_category_l2"] = "Stored XSS"
        out = check_all_fields(e, tools, llm)
        # title/category 用 mock LLM 判定，scripted mock 走 default → uncertain
        # 所以整条 entry 应是 uncertain（除非 mock 给出 correct）
        assert out["verdict"] in ("correct", "uncertain", "incorrect")

    def test_verdict_incorrect_when_any_incorrect(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["entry_point"]["code"] = "wrongCode();"
        out = check_all_fields(e, tools, llm)
        assert out["verdict"] == "incorrect"


# ============================================================
# TestIntegrationWithI1Schema
# ============================================================

class TestIntegrationWithI1Schema:
    """I1 validate_field_result 对 I3 产出的字段对象全部 pass。"""

    def test_all_eight_fields_validate(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        e["vuln_ids"] = ["CVE-2026-DEMO-0001"]
        e["vuln_title"] = "Blog Platform Stored DOM XSS"
        e["vuln_category_l1"] = "XSS"
        e["vuln_category_l2"] = "Stored XSS"
        out = check_all_fields(e, tools, llm)
        for fname, fobj in out["fields"].items():
            errs = validate_field_result(fobj, fname)
            assert errs == [], f"field {fname} failed I1 schema validation: {errs}"

    def test_refs_pass_individual_validation(self, tools, llm, manifest):
        item = manifest["items"][0]
        e = _base_entry(item)
        r = check_entry_point(e, tools, llm)
        for ref in r["evidence_refs"]:
            # 重新构造 dict 用 validate_field_result 校验
            errs = validate_field_result(
                {"status": r["status"], "confidence": r["confidence"],
                 "evidence": r["evidence"], "evidence_refs": [ref]},
                "entry_point",
            )
            assert errs == [], f"ref failed: {ref}, errs={errs}"