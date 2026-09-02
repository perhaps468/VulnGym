# -*- coding: utf-8 -*-
"""工具集：read_advisory / checkout / read_file_lines / grep_code / git_log。

所有工具都是纯本地（无网络），输入严格，输出严格 JSON。
被 Agent 调用，对应 VulnGym 题目要求的"至少 3 类工具"。
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ToolResult:
    name: str
    ok: bool
    data: Any
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "data": self.data, "error": self.error}


class VulnGymTools:
    """封装 demo 用到的全部工具。

    repo_cache_dir:  <project>/<commit>/<file> 形式的本地仓库缓存根目录
    advisory_dir:    本地公告缓存目录 (json per GHSA-id)
    """

    def __init__(self, repo_cache_dir: Path, advisory_dir: Path) -> None:
        self.repo_cache_dir = Path(repo_cache_dir)
        self.advisory_dir = Path(advisory_dir)

    # ---------- 1. read_advisory ----------
    def read_advisory(self, report_id: str) -> ToolResult:
        fp = self.advisory_dir / f"{report_id}.json"
        if not fp.exists():
            return ToolResult("read_advisory", False, None, f"advisory not found: {fp}")
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
        return ToolResult("read_advisory", True, data)

    # ---------- 2. checkout ----------
    # mock 实现：把 commit 当成目录名直接切换，不依赖 git。
    def checkout(self, project: str, commit: str) -> ToolResult:
        if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
            return ToolResult("checkout", False, None, f"bad commit format: {commit!r}")
        path = self.repo_cache_dir / project / commit
        if not path.exists():
            return ToolResult(
                "checkout", False, None,
                f"commit not in local cache: {path}",
            )
        return ToolResult("checkout", True, {"cwd": str(path), "commit": commit})

    # ---------- 3. read_file_lines ----------
    def read_file_lines(self, cwd: str, file: str, start: int, end: int) -> ToolResult:
        path = Path(cwd) / file
        if not path.exists():
            return ToolResult("read_file_lines", False, None, f"file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        s, e = max(1, start), min(len(lines), end)
        snippet = "".join(lines[s - 1 : e])
        return ToolResult(
            "read_file_lines", True,
            {"file": file, "start": s, "end": e, "snippet": snippet, "total_lines": len(lines)},
        )

    # ---------- 4. grep_code ----------
    def grep_code(self, cwd: str, file: str, pattern: str) -> ToolResult:
        path = Path(cwd) / file
        if not path.exists():
            return ToolResult("grep_code", False, None, f"file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        hits = []
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return ToolResult("grep_code", False, None, f"bad regex: {e}")
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                hits.append({"line": i, "text": line.rstrip("\n")})
        return ToolResult("grep_code", True, {"file": file, "pattern": pattern, "hits": hits})

    # ---------- 5. git_log (mock) ----------
    def git_log(self, project: str, commit: str, limit: int = 5) -> ToolResult:
        # mock：返回包含当前 commit 的若干条历史
        entries = [
            {"sha": commit, "author": "alice@example.com", "message": f"introduce: {project} change at {commit[:7]}"},
            {"sha": "0" * 40, "author": "bob@example.com", "message": "previous: cleanups"},
            {"sha": "1" * 40, "author": "carol@example.com", "message": "earlier: refactor"},
        ]
        return ToolResult("git_log", True, entries[:limit])


def normalize_project_from_repo(repo_url: str) -> str:
    """repo_url -> project key (用于 mock 仓库目录)。

    例: https://github.com/example/blog-platform -> blog-platform
    """
    return repo_url.rstrip("/").split("/")[-1].replace(".git", "")