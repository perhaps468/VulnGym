# -*- coding: utf-8 -*-
"""工具集：read_advisory / checkout / read_file_lines / grep_code / git_log。

所有工具都是纯本地（无网络），输入严格，输出严格 JSON。
被 Agent 调用，对应 VulnGym 题目要求的"至少 3 类工具"。

I2 升级：
  * 可选 manifest 参数：repo_url 通过 manifest 解析到唯一 project key，防 collision
  * 路径安全：用 Path.resolve().is_relative_to() 严格校验 cwd 与 file
  * 4 类失败（404 / 权限 / 坏 JSON / 坏 commit）全部 ToolResult(ok=false)，不抛异常
  * git_log 在 commit 不在 manifest 时返回 ok=false
  * 无网络：不 import requests/urllib/socket/http.client/aiohttp
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================
# 异常与 manifest 加载
# ============================================================


class UnknownProjectError(KeyError):
    """repo_url 不在 manifest 中，或 manifest 缺失/格式错。"""


def load_manifest(path: Path | str) -> Dict[str, Any]:
    """读取 mock_repo/manifest.json。返回 dict，必须含 'items' 列表。"""
    fp = Path(path)
    if not fp.exists():
        raise FileNotFoundError(f"manifest not found: {fp}")
    with open(fp, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "items" not in data or not isinstance(data["items"], list):
        raise ValueError(f"manifest schema error: missing 'items' list in {fp}")
    # 校验每个 item 的必填字段
    required = {"repo_url", "project", "commit", "version", "role"}
    for it in data["items"]:
        if not required.issubset(it.keys()):
            raise ValueError(f"manifest item missing required fields: {it}")
        if it["role"] not in {"vulnerable", "fixed", "unknown"}:
            raise ValueError(f"bad role in manifest item: {it}")
        if not re.fullmatch(r"[0-9a-f]{40}", it["commit"]):
            raise ValueError(f"bad commit in manifest item: {it}")
    return data


def _canonical_repo_url(repo_url: str) -> str:
    """规范化 repo_url：
    - 去除尾部 '/' 和 '.git'
    - 保留 owner/name（不做大小写折叠——保持用户原值精确匹配）
    - 去掉 /tree/... 等附加 path（只取 owner/name）
    """
    u = (repo_url or "").strip().rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    # 提取 owner/name
    parts = u.split("/")
    # 找到 github.com 后两段
    for i, seg in enumerate(parts):
        if seg in {"github.com", "gitlab.com", "bitbucket.org"} and i + 2 < len(parts):
            return "{}/{}/{}".format("/".join(parts[: i + 1]), parts[i + 1], parts[i + 2])
    # 兜底：取最后两段
    return "/".join(parts[-2:]) if len(parts) >= 2 else u


def normalize_project_from_repo(
    repo_url: str, manifest: Optional[Dict[str, Any]] = None,
) -> str:
    """repo_url -> project key。

    manifest 提供时严格按 repo_url 查 manifest 唯一映射（防 collision）。
    manifest=None 或空 items 时回退到 basename（兼容 I1 旧调用）。
    """
    if manifest and manifest.get("items"):
        key = _canonical_repo_url(repo_url)
        for entry in manifest["items"]:
            if _canonical_repo_url(entry["repo_url"]) == key:
                return entry["project"]
        raise UnknownProjectError(f"repo_url not in manifest: {repo_url!r}")
    # fallback（无 manifest 或空 manifest）
    return (
        repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        if repo_url else ""
    )


# ============================================================
# ToolResult 与 VulnGymTools
# ============================================================


@dataclass
class ToolResult:
    name: str
    ok: bool
    data: Any
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "data": self.data, "error": self.error}


# 合法 GHSA-id 格式：GHSA-xxxx-xxxx-xxxx（4 段字符）。简化用 [A-Z0-9-]+ 但禁止 . 和 ..
_GHSA_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]*$")
_HEX40 = re.compile(r"[0-9a-f]{40}")


class VulnGymTools:
    """封装 demo 用到的全部工具。

    repo_cache_dir:  <project>/<commit>/<file> 形式的本地仓库缓存根目录
    advisory_dir:    本地公告缓存目录 (json per GHSA-id)
    manifest:        可选 dict，启用 repo_url -> project 严格映射
    """

    def __init__(
        self,
        repo_cache_dir: Path | str,
        advisory_dir: Path | str,
        manifest: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.repo_cache_dir = Path(repo_cache_dir).resolve()
        self.advisory_dir = Path(advisory_dir).resolve()
        self.manifest = manifest

    # ---------- 1. read_advisory ----------
    def read_advisory(self, report_id: str) -> ToolResult:
        # 格式校验：拒绝路径穿越字符
        if not report_id or not _GHSA_ID_RE.fullmatch(report_id):
            return ToolResult(
                "read_advisory", False, None,
                f"bad report_id format: {report_id!r}",
            )
        if "/" in report_id or "\\" in report_id or ".." in report_id:
            return ToolResult(
                "read_advisory", False, None,
                f"path traversal in report_id: {report_id!r}",
            )
        fp = self.advisory_dir / f"{report_id}.json"
        # 防止逃逸到 advisory_dir 之外
        try:
            fp_resolved = fp.resolve()
        except OSError:
            return ToolResult("read_advisory", False, None, f"advisory path invalid: {fp}")
        if not str(fp_resolved).startswith(str(self.advisory_dir)):
            return ToolResult(
                "read_advisory", False, None,
                f"advisory path escape: {fp}",
            )
        if not fp_resolved.exists():
            return ToolResult("read_advisory", False, None, f"advisory not found: {report_id}")
        try:
            with open(fp_resolved, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return ToolResult("read_advisory", False, None, f"advisory json decode failed: {e}")
        except (PermissionError, OSError) as e:
            return ToolResult("read_advisory", False, None, f"advisory read failed: {e}")
        return ToolResult("read_advisory", True, data)

    # ---------- 2. checkout ----------
    def checkout(self, project: str, commit: str) -> ToolResult:
        if not _HEX40.fullmatch(commit or ""):
            return ToolResult("checkout", False, None, f"bad commit format: {commit!r}")
        # project 必须非空、不含 / 或 ..（防路径穿越）
        if not project or "/" in project or "\\" in project or ".." in project:
            return ToolResult("checkout", False, None, f"bad project key: {project!r}")
        # manifest 校验：(project, commit) 联合 key 必须存在
        if self.manifest and self.manifest.get("items"):
            declared = any(
                e["project"] == project and e["commit"] == commit
                for e in self.manifest["items"]
            )
            if not declared:
                return ToolResult(
                    "checkout", False, None,
                    f"(project={project}, commit={commit[:7]}) not declared in manifest",
                )
        path = (self.repo_cache_dir / project / commit).resolve()
        # 严格校验路径在 repo_cache_dir 之内
        try:
            if not path.is_relative_to(self.repo_cache_dir):
                return ToolResult("checkout", False, None, f"checkout path escape: {path}")
        except (OSError, ValueError):
            return ToolResult("checkout", False, None, f"checkout path invalid: {path}")
        if not path.exists() or not path.is_dir():
            return ToolResult("checkout", False, None, f"commit not in local cache: {path}")
        return ToolResult("checkout", True, {"cwd": str(path), "commit": commit})

    # ---------- 3. read_file_lines ----------
    def read_file_lines(self, cwd: str, file: str, start: int, end: int) -> ToolResult:
        if not file or file.startswith("/") or "\\" in file or ".." in file.split("/"):
            return ToolResult(
                "read_file_lines", False, None,
                f"bad file path: {file!r}",
            )
        try:
            cwd_resolved = Path(cwd).resolve()
            file_path = (cwd_resolved / file).resolve()
        except (OSError, ValueError) as e:
            return ToolResult("read_file_lines", False, None, f"path invalid: {e}")
        # cwd 必须严格在 repo_cache_dir 之内
        try:
            if not cwd_resolved.is_relative_to(self.repo_cache_dir):
                return ToolResult(
                    "read_file_lines", False, None,
                    f"cwd outside repo_cache: {cwd}",
                )
        except (OSError, ValueError):
            return ToolResult("read_file_lines", False, None, f"cwd invalid: {cwd}")
        # file 必须仍在 cwd 之下
        try:
            if not file_path.is_relative_to(cwd_resolved):
                return ToolResult(
                    "read_file_lines", False, None,
                    f"file path escape: {file}",
                )
        except (OSError, ValueError):
            return ToolResult("read_file_lines", False, None, f"file path invalid: {file}")
        if not file_path.exists():
            return ToolResult("read_file_lines", False, None, f"file not found: {file}")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (PermissionError, OSError) as e:
            return ToolResult("read_file_lines", False, None, f"file read failed: {e}")
        try:
            s, e = int(start), int(end)
        except (TypeError, ValueError):
            return ToolResult("read_file_lines", False, None, f"bad range: {start}-{end}")
        s, e = max(1, s), min(len(lines), e)
        if s > e:
            return ToolResult(
                "read_file_lines", True,
                {"file": file, "start": s, "end": e, "snippet": "", "total_lines": len(lines)},
            )
        snippet = "".join(lines[s - 1 : e])
        return ToolResult(
            "read_file_lines", True,
            {"file": file, "start": s, "end": e, "snippet": snippet, "total_lines": len(lines)},
        )

    # ---------- 4. grep_code ----------
    def grep_code(self, cwd: str, file: str, pattern: str) -> ToolResult:
        # 复用 read_file_lines 的安全检查
        rdl = self.read_file_lines(cwd, file, 1, 10**9)
        if not rdl.ok:
            # 用 grep_code 的名字包装
            return ToolResult("grep_code", False, None, rdl.error)
        # 此时 cwd+file 已经验证过安全，但 read_file_lines 返回了全文 snippet，再展开读一次拿 line-by-line
        try:
            cwd_resolved = Path(cwd).resolve()
            file_path = (cwd_resolved / file).resolve()
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (PermissionError, OSError) as e:
            return ToolResult("grep_code", False, None, f"file read failed: {e}")
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return ToolResult("grep_code", False, None, f"bad regex: {e}")
        hits = []
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                hits.append({"line": i, "text": line.rstrip("\n")})
        return ToolResult("grep_code", True, {"file": file, "pattern": pattern, "hits": hits})

    # ---------- 5. git_log (mock) ----------
    def git_log(self, project: str, commit: str, limit: int = 5) -> ToolResult:
        if not _HEX40.fullmatch(commit or ""):
            return ToolResult("git_log", False, None, f"bad commit format: {commit!r}")
        # 必须 commit 在 manifest 或 (project, commit) 在缓存
        if self.manifest and self.manifest.get("items"):
            ok = any(
                e["project"] == project and e["commit"] == commit
                for e in self.manifest["items"]
            )
            if not ok:
                return ToolResult(
                    "git_log", False, None,
                    f"(project={project}, commit={commit[:7]}) not declared",
                )
        entries = [
            {"sha": commit, "author": "alice@example.com",
             "message": f"introduce: {project} change at {commit[:7]}"},
            {"sha": "0" * 40, "author": "bob@example.com",
             "message": "previous: cleanups"},
            {"sha": "1" * 40, "author": "carol@example.com",
             "message": "earlier: refactor"},
            {"sha": "2" * 40, "author": "dave@example.com",
             "message": "earlier still: init"},
            {"sha": "3" * 40, "author": "eve@example.com",
             "message": "oldest: bootstrap"},
            {"sha": "4" * 40, "author": "frank@example.com",
             "message": "ancient: scaffold"},
        ]
        # limit 上限 10（防止内存滥用）
        cap = min(max(int(limit or 0), 1), 10)
        return ToolResult("git_log", True, entries[:cap])