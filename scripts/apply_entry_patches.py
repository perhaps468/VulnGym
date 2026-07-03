#!/usr/bin/env python3
"""Generate rebuild patch for 5 misaligned VulnGym entries.

Reads `data/entries.jsonl`, rewrites the five semantically-misaligned lines in
place (everything else is passed through), and writes the result back to
`data/entries.jsonl`, plus a field-level diff (`fix_diff.csv`) and a JSON
report (`examples/report.json`).

The rewritten entries follow `SCHEMA.md`: file/line/code match the listed
commit, desc explains the node's role in the chain, and trace nodes are
limited to lines that actually participate in the exploit.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRIES_PATH = REPO_ROOT / "data" / "entries.jsonl"
OUT_DIFF = REPO_ROOT / "fix_diff.csv"
OUT_REPORT = REPO_ROOT / "examples" / "report.json"

# ---------------------------------------------------------------------------
# Patch definitions
# ---------------------------------------------------------------------------

PATCHES: dict[str, dict] = {
    "entry-00185": {
        "summary": (
            "Rewrite n8n ReadWriteFile -> .git/config RCE chain: lift"
            " entry/critical/trace to match entry-00186 (same advisory)."
        ),
        "fields": {
            "entry_point": {
                "file": "packages/nodes-base/nodes/Files/ReadWriteFile/actions/write.operation.ts",
                "line": 70,
                "code": "\t\t\tfileName = this.getNodeParameter('fileName', itemIndex) as string;",
                "desc": (
                    "getNodeParameter 在 execute 的逐项循环内读取用户提交的 fileName"
                    " 参数，将原始字符串值直接赋给本地变量并向调用栈下游传递。"
                    "此处对路径内容不施加任何格式或语义校验，安全决策完全委托给下游辅助层；"
                    "在漏洞链路中，这是攻击者可控的目标路径值首次进入写入执行流的位置，"
                    "也是后续全部攻击步骤的数据源头。"
                ),
            },
            "critical_operation": {
                "file": "packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts",
                "line": 61,
                "code": "\tif (allowedPaths.length) {",
                "desc": (
                    "isFilePathBlocked 的 allowedPaths 条件分支是文件路径访问控制的核心判定节点："
                    "仅当 allowedPaths 非空时才进入基于包含关系的合法性判定，随后调用 isContainedWithin"
                    " 做最终裁决。该分支仅实现 allowlist 过滤，对 .git 目录没有专项屏蔽；"
                    "在漏洞链路中，此处是决定 resolvedFilePath 能否抵达写入层的唯一路径检查点，"
                    "其对 .git 子路径的静默放行使恶意配置写入成为可能。"
                ),
            },
            "trace": [
                {
                    "file": "packages/nodes-base/nodes/Files/ReadWriteFile/actions/write.operation.ts",
                    "line": "62-71",
                    "code": "export async function execute(this: IExecuteFunctions, items: INodeExecutionData[]) {\n\tconst returnData: INodeExecutionData[] = [];\n\tlet fileName;\n\n\tlet item: INodeExecutionData;\n\tfor (let itemIndex = 0; itemIndex < items.length; itemIndex++) {\n\t\ttry {\n\t\t\tconst dataPropertyName = this.getNodeParameter('dataPropertyName', itemIndex);\n\t\t\tfileName = this.getNodeParameter('fileName', itemIndex) as string;\n\t\t\tconst options = this.getNodeParameter('options', itemIndex, {});",
                    "desc": (
                        "execute() 是写操作调用链的 caller 端起点，从此处向文件系统辅助函数发起写入请求："
                        "函数体遍历输入数据项，通过 getNodeParameter 依次读取 dataPropertyName 与 fileName，"
                        "随后将路径值向辅助层传递。这一段覆盖从节点参数采集到辅助层入口的全程，fileName"
                        " 在此处未经任何校验即离开节点层；在漏洞链路中，该段确立了用户可控路径进入"
                        " 安全检测函数的前提，是整条利用序列的第一跳。"
                    ),
                },
                {
                    "file": "packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts",
                    "line": "61-63",
                    "code": "\tif (allowedPaths.length) {\n\t\treturn !allowedPaths.some((allowedPath) => isContainedWithin(allowedPath, resolvedFilePath));\n\t}",
                    "desc": (
                        "随后在 isFilePathBlocked 函数体（caller）内，allowedPaths 条件块调用"
                        " isContainedWithin（callee）对 resolvedFilePath 执行包含关系检测，"
                        "决定是否向上层返回阻断标志。该段位于 execute 路径传入之后、fsWriteFile 落盘之前，"
                        "是整条调用链中仅有的路径访问控制节点；其逻辑仅覆盖 allowlist 场景且对"
                        " .git 子目录无专项拦截，是漏洞链路中应阻断而实际放行恶意路径的关键缺陷位置。"
                    ),
                },
                {
                    "file": "packages/core/src/execution-engine/node-execution-context/utils/file-system-helper-functions.ts",
                    "line": "128-132",
                    "code": "\t\treturn await fsWriteFile(resolvedFilePath, content, {\n\t\t\tencoding: 'binary',\n\t\t\tflag: (flag ?? 0) | constants.O_NOFOLLOW,\n\t\t});\n\t},",
                    "desc": (
                        "在调用栈下游，此段由辅助函数内部 caller 向 fsWriteFile callee 移交最终写入控制权，"
                        "以 binary 编码和 O_NOFOLLOW 标志将 content 落盘到 resolvedFilePath，"
                        "随后无任何安全门控介入。由于 isFilePathBlocked 在前序步骤中未拦截 .git 目录路径，"
                        "fsWriteFile 于此处成为漏洞链路中恶意内容被实际持久化到目标文件的最终执行节点。"
                    ),
                },
            ],
        },
        "verify": 1,
    },
    "entry-00197": {
        "summary": (
            "Refine openclaw sandbox TOCTOU: tighten critical_operation"
            " desc and lift entry_point to the route handler line."
        ),
        "fields": {
            "entry_point": {
                "file": "src/media/server.ts",
                "line": "35-36",
                "code": "  app.get(\"/media/:id\", async (req, res) => {\n    const id = req.params.id;",
                "desc": (
                    "app.get('/media/:id', ...) registers the Express route for media retrieval;"
                    " req.params.id captures the caller-supplied URL segment and binds it to id."
                    " This handler is the top of the call chain leading to the sandbox check"
                    " (openFileWithinRoot + stat size/mtime) and the subsequent unguarded file"
                    " read, making id the externally-controlled taint source for the entire"
                    " TOCTOU pair."
                ),
            },
            "critical_operation": {
                "file": "src/media/server.ts",
                "line": 57,
                "code": "      const data = await handle.readFile();",
                "desc": (
                    "handle.readFile() reads the full content of the file opened earlier by"
                    " openFileWithinRoot. This is the use phase of the TOCTOU pair: without"
                    " re-validating the sandbox boundary at read time, a symlink substituted"
                    " between the check step and this call redirects the read to an arbitrary"
                    " file outside the sandbox root, delivering its contents to the HTTP"
                    " response."
                ),
            },
            "trace": [
                {
                    "file": "src/media/server.ts",
                    "line": "35-36",
                    "code": "  app.get(\"/media/:id\", async (req, res) => {\n    const id = req.params.id;",
                    "desc": (
                        "Express route registration for GET /media/:id is the externally"
                        " reachable entry; req.params.id is the attacker-controlled string"
                        " that proceeds unchecked into the sandbox resolver."
                    ),
                },
                {
                    "file": "src/media/server.ts",
                    "line": 37,
                    "code": "    if (!isValidMediaId(id)) {",
                    "desc": (
                        "isValidMediaId performs only a syntactic shape check on id; any"
                        " well-formed value whose filesystem target is a symlink still"
                        " passes, so the subsequent check in openFileWithinRoot must rely on"
                        " realpath to detect escapes."
                    ),
                },
                {
                    "file": "src/media/server.ts",
                    "line": "42-45",
                    "code": "      const { handle, realPath, stat } = await openFileWithinRoot({\n        rootDir: mediaDir,\n        relativePath: id,\n      });",
                    "desc": (
                        "openFileWithinRoot is the check phase: it realpath-resolves id against"
                        " the mediaDir root and returns a handle plus stat. The handle exposes"
                        " a file descriptor that survives beyond this call, opening the TOCTOU"
                        " window."
                    ),
                },
                {
                    "file": "src/media/server.ts",
                    "line": 51,
                    "code": "      if (Date.now() - stat.mtimeMs > ttlMs) {",
                    "desc": (
                        "TTL sanity check based on stat.mtimeMs that runs after"
                        " openFileWithinRoot. It is an *eviction* decision, not a boundary"
                        " check, so swapping the symlink between the realpath in"
                        " openFileWithinRoot and handle.readFile() below is not detected."
                    ),
                },
                {
                    "file": "src/media/server.ts",
                    "line": 57,
                    "code": "      const data = await handle.readFile();",
                    "desc": (
                        "handle.readFile() is the use phase of the TOCTOU pair: if between"
                        " openFileWithinRoot and this read the attacker swaps the path on"
                        " disk for a symlink outside the sandbox root, the kernel will"
                        " dereference the symlink via the live fd and the response will"
                        " contain whatever arbitrary file the attacker chose."
                    ),
                },
            ],
        },
        "verify": 1,
    },
    "entry-00290": {
        "summary": (
            "Align with maintainer note: keep resolveSymlinkHopPath as"
            " the fail-open decision point and rewrite trace so the"
            " applyPatch sink is visible alongside the check."
        ),
        "fields": {
            "entry_point": {
                "file": "src/agents/apply-patch.ts",
                "line": 94,
                "code": "    execute: async (_toolCallId, args, signal) => {",
                "desc": (
                    "execute is the asynchronous entry point registered for the"
                    " apply_patch tool; it accepts the AI-supplied tool-call payload"
                    " (input/patch) and dispatches it through the patch application"
                    " pipeline. In the vulnerability chain this is where"
                    " attacker-controlled patch strings first enter the patch runner"
                    " before any sandbox boundary check is performed."
                ),
            },
            "critical_operation": {
                "file": "src/infra/boundary-path.ts",
                "line": 196,
                "code": "    const linkCanonical = await resolveSymlinkHopPath(lexicalCursor);",
                "desc": (
                    "resolveSymlinkHopPath is the fail-open decision point at the heart"
                    " of the dangling-symlink sandbox escape. When the symbol it follows"
                    " resolves to a non-existent target, realpath raises ENOENT and the"
                    " function instead returns the lexical (symlink-bearing) path of the"
                    " unresolved link (definition at boundary-path.ts:487-498 — catch"
                    " branch reads via fsp.readlink and resolves the result without"
                    " raising). The result still appears to lie inside the sandbox on a"
                    " path-prefix check, so the subsequent isPathInside assertion"
                    " silently approves an out-of-tree write target. Per the maintainer"
                    " note this node is the *check* whose absence of a hard-fail branch"
                    " constitutes the defect; the actual file-system mutation occurs at"
                    " the applyPatch sink downstream, which is captured in the trace."
                ),
            },
            "trace": [
                {
                    "file": "src/agents/apply-patch.ts",
                    "line": 94,
                    "code": "    execute: async (_toolCallId, args, signal) => {",
                    "desc": (
                        "execute() is the tool-call entry: attacker-controlled patch"
                        " content arrives here and is forwarded to applyPatch without"
                        " prior boundary validation."
                    ),
                },
                {
                    "file": "src/agents/apply-patch.ts",
                    "line": "106-111",
                    "code": "      const result = await applyPatch(input, {\n        cwd,\n        sandbox,\n        workspaceOnly,\n        signal,\n      });",
                    "desc": (
                        "execute() forwards the untrusted input to applyPatch together"
                        " with the sandbox config; from this call onward each hunk's"
                        " path goes through resolvePatchPath -> resolveBoundaryPath."
                    ),
                },
                {
                    "file": "src/agents/apply-patch.ts",
                    "line": 150,
                    "code": "      const target = await resolvePatchPath(hunk.path, options);",
                    "desc": (
                        "Inside the add-hunk branch, resolvePatchPath returns the"
                        " lexical path that flows into boundary-path.ts; this is the"
                        " symbolic propagation step that carries dangling-symlink"
                        " components into the boundary resolver."
                    ),
                },
                {
                    "file": "src/infra/boundary-path.ts",
                    "line": 196,
                    "code": "    const linkCanonical = await resolveSymlinkHopPath(lexicalCursor);",
                    "desc": (
                        "resolveSymlinkHopPath is the fail-open decision point: when"
                        " realpath raises ENOENT the helper falls back to the"
                        " symlink's lexical location, returning a path that is still"
                        " inside the sandbox prefix. The subsequent isPathInside"
                        " therefore approves the write even though the live target may"
                        " be outside."
                    ),
                },
                {
                    "file": "src/agents/apply-patch.ts",
                    "line": 152,
                    "code": "      await fileOps.writeFile(target.resolved, hunk.contents);",
                    "desc": (
                        "fileOps.writeFile is the terminal sink for the add-hunk"
                        " branch. target.resolved has already been approved by the"
                        " boundary check at this point, but because"
                        " resolveSymlinkHopPath returned a sandbox-internal lexical path"
                        " for a dangling link, the kernel resolves the trailing symlink"
                        " hop and writes outside the workspace root."
                    ),
                },
            ],
        },
        "verify": 1,
    },
    "entry-00391": {
        "summary": (
            "Re-anchor fastmcp OpenAPIProvider path-traversal:"
            " critical_operation moves from the _build_url declaration"
            " to the actual replace()/urljoin() site, trace follows"
            " the concrete code flow."
        ),
        "fields": {
            "entry_point": {
                "file": "src/fastmcp/utilities/openapi/director.py",
                "line": "23-28",
                "code": "    def build(\n        self,\n        route: HTTPRoute,\n        flat_args: dict[str, Any],\n        base_url: str = \"http://localhost\",\n    ) -> httpx.Request:",
                "desc": (
                    "build() is RequestDirector's public request-construction entry"
                    " point. It receives flat_args and base_url from MCP tool dispatch"
                    " and routes them through _unflatten_arguments and _build_url; this"
                    " method marks the first point where caller-controlled parameter"
                    " values enter the URL assembly pipeline without any encoding step."
                ),
            },
            "critical_operation": {
                "file": "src/fastmcp/utilities/openapi/director.py",
                "line": "194-216",
                "code": "    def _build_url(\n        self, path_template: str, path_params: dict[str, Any], base_url: str\n    ) -> str:\n        \"\"\"\n        Build URL by substituting path parameters in the template.\n\n        Args:\n            path_template: OpenAPI path template (e.g., \"/users/{id}\")\n            path_params: Path parameter values\n            base_url: Base URL to prepend\n\n        Returns:\n            Complete URL with path parameters substituted\n        \"\"\"\n        # Substitute path parameters\n        url_path = path_template\n        for param_name, param_value in path_params.items():\n            placeholder = f\"{{{param_name}}}\"\n            if placeholder in url_path:\n                url_path = url_path.replace(placeholder, str(param_value))\n\n        # Combine with base URL\n        return urljoin(base_url.rstrip(\"/\") + \"/\", url_path.lstrip(\"/\"))",
                "desc": (
                    "_build_url performs textual substring substitution into the path"
                    " template (no urllib.parse.quote) and then resolves the result via"
                    " urljoin. The replace call (line 213) is the precise sink where a"
                    " path_params value containing '../' is pasted verbatim into the URL"
                    " template, and urljoin's path normalisation against base_url"
                    " collapses the traversal sequence to escape the OpenAPI-defined"
                    " endpoint prefix. Per the maintainer note this exact location, not"
                    " the method declaration, is the right anchor for the critical"
                    " operation."
                ),
            },
            "trace": [
                {
                    "file": "src/fastmcp/utilities/openapi/director.py",
                    "line": "23-28",
                    "code": "    def build(\n        self,\n        route: HTTPRoute,\n        flat_args: dict[str, Any],\n        base_url: str = \"http://localhost\",\n    ) -> httpx.Request:",
                    "desc": (
                        "build() declares the externally reachable entry: the four"
                        " parameter slots mark where the flat_args dict first arrives"
                        " at RequestDirector. After this point the values are forwarded"
                        " through _unflatten_arguments without any encoding."
                    ),
                },
                {
                    "file": "src/fastmcp/utilities/openapi/director.py",
                    "line": "53-54",
                    "code": "        # Step 2: Build base URL with path parameters\n        url = self._build_url(route.path, path_params, base_url)",
                    "desc": (
                        "After _unflatten_arguments splits flat_args into"
                        " path/query/header/body the call site at L54 hands the route"
                        " template plus the path_params subset to _build_url. The"
                        " traversal payload enters _build_url here without further"
                        " inspection."
                    ),
                },
                {
                    "file": "src/fastmcp/utilities/openapi/director.py",
                    "line": "208-213",
                    "code": "        # Substitute path parameters\n        url_path = path_template\n        for param_name, param_value in path_params.items():\n            placeholder = f\"{{{param_name}}}\"\n            if placeholder in url_path:\n                url_path = url_path.replace(placeholder, str(param_value))",
                    "desc": (
                        "Inside _build_url, the for-loop substitutes each path_params"
                        " value into the template via raw replace — no"
                        " urllib.parse.quote. A value of '../admin' lands verbatim on"
                        " url_path, ready to be collapsed by the urljoin that follows."
                    ),
                },
                {
                    "file": "src/fastmcp/utilities/openapi/director.py",
                    "line": 213,
                    "code": "                url_path = url_path.replace(placeholder, str(param_value))",
                    "desc": (
                        "Single-line view of the splice site: this is the line that"
                        " physically pastes the attacker's string into the URL"
                        " template. Listed as its own trace node to keep the variant"
                        " annotations tractable when the surrounding function shifts in"
                        " later commits."
                    ),
                },
                {
                    "file": "src/fastmcp/utilities/openapi/director.py",
                    "line": "215-216",
                    "code": "        # Combine with base URL\n        return urljoin(base_url.rstrip(\"/\") + \"/\", url_path.lstrip(\"/\"))",
                    "desc": (
                        "urljoin applies path normalisation against base_url, which"
                        " folds the embedded '../' traversal segment, producing a final"
                        " URL that points outside the OpenAPI-defined endpoint surface."
                        " The malformed url is then returned to the caller, completing"
                        " the path-traversal SSRF."
                    ),
                },
            ],
        },
        "verify": 1,
    },
    "entry-00320": {
        "summary": (
            "Match entry-00321 (same advisory): lift entry_point to"
            " the multipart filename capture and re-anchor"
            " critical_operation at folder_path / file_name."
        ),
        "fields": {
            "entry_point": {
                "file": "src/backend/base/langflow/api/v2/files.py",
                "line": 122,
                "code": "        file_name = file.filename",
                "desc": (
                    "Within save_file_routine, when no file_name override is"
                    " supplied the multipart Content-Disposition filename"
                    " (file.filename) is assigned directly to the internal"
                    " file_name variable. The captured value is forwarded to"
                    " storage_service.save_file without any path validation, making"
                    " this assignment the taint origin of the traversal chain. The"
                    " maintainer note explicitly asked to lift the entry point up to"
                    " where attacker input enters; this line is exactly that"
                    " boundary."
                ),
            },
            "critical_operation": {
                "file": "src/backend/base/langflow/services/storage/local.py",
                "line": 116,
                "code": "        file_path = folder_path / file_name",
                "desc": (
                    "`folder_path / file_name` (pathlib join) concatenates the storage"
                    " root with the unvalidated file_name. pathlib silently collapses"
                    " the embedded '../' components, so the resulting Path object"
                    " points outside the storage sandbox. This is the storage-layer"
                    " decision point that translates the API-level input into an"
                    " arbitrary filesystem path; the subsequent async_open opens this"
                    " resolved path for writing, delivering the arbitrary-write"
                    " primitive."
                ),
            },
            "trace": [
                {
                    "file": "src/backend/base/langflow/api/v2/files.py",
                    "line": 122,
                    "code": "        file_name = file.filename",
                    "desc": (
                        "file.filename is taken verbatim from the multipart header"
                        " and reassigned to file_name when no override is supplied;"
                        " traversal sequences such as '../etc/passwd' survive this"
                        " step intact."
                    ),
                },
                {
                    "file": "src/backend/base/langflow/api/v2/files.py",
                    "line": "163-166",
                    "code": "        try:\n            root_filename, file_extension = new_filename.rsplit(\".\", 1)\n        except ValueError:\n            root_filename, file_extension = new_filename, \"\"",
                    "desc": (
                        "rsplit('.', 1) splits the captured file_name purely by"
                        " extension convention; it never inspects the value for path"
                        " separators, so the traversal payload remains present in"
                        " root_filename and propagates to the dedup step."
                    ),
                },
                {
                    "file": "src/backend/base/langflow/api/v2/files.py",
                    "line": "205-214",
                    "code": "                for my_file in files:\n                    match = re.search(r\"\\((\\d+)\\)(?=\\.\\w+$|$)\", my_file.name)\n                    if match:\n                        counts.append(int(match.group(1)))\n\n                count = max(counts) if counts else 0\n                root_filename = f\"{root_filename} ({count + 1})\"\n\n            # Create the unique filename with extension for storage\n            unique_filename = f\"{root_filename}.{file_extension}\" if file_extension else root_filename",
                    "desc": (
                        "Dedup logic only matches the trailing parenthesised counter;"
                        " '../' segments are unaffected, so the constructed"
                        " unique_filename still carries the traversal payload."
                    ),
                },
                {
                    "file": "src/backend/base/langflow/services/storage/local.py",
                    "line": 116,
                    "code": "        file_path = folder_path / file_name",
                    "desc": (
                        "`folder_path / file_name` is the path-assembly step that"
                        " converts the API-level traversal payload into a pathlib"
                        " Path referencing an arbitrary filesystem location; this is"
                        " the critical decision point of the storage side."
                    ),
                },
                {
                    "file": "src/backend/base/langflow/services/storage/local.py",
                    "line": 120,
                    "code": "            async with async_open(str(file_path), mode) as f:",
                    "desc": (
                        "async_open opens the resolved file_path for writing in"
                        " binary mode and writes the request payload to it; this is"
                        " the terminal sink that materialises the arbitrary-write"
                        " primitive on disk, completing the chain."
                    ),
                },
            ],
        },
        "verify": 1,
    },
}


def rewrite_entry(entry: dict, patch: dict) -> dict:
    """Apply a patch to a single entry object, preserving untouched fields."""
    for key, value in patch["fields"].items():
        entry[key] = value
    if "verify" in patch:
        entry["verify"] = patch["verify"]
    return entry


def main() -> int:
    if not ENTRIES_PATH.is_file():
        print(f"entries file not found: {ENTRIES_PATH}", file=sys.stderr)
        return 1

    targeted = set(PATCHES.keys())
    diff_rows: list[dict] = []
    fixes_report: list[dict] = []
    new_lines: list[str] = []

    with ENTRIES_PATH.open("r", encoding="utf-8") as src:
        for raw in src:
            line = raw.rstrip("\n")
            if not line.strip():
                new_lines.append(raw)
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                new_lines.append(raw)
                continue

            entry_id = entry.get("entry_id")
            if entry_id not in targeted:
                new_lines.append(raw)
                continue

            patch = PATCHES[entry_id]
            entry = rewrite_entry(entry, patch)

            new_line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
            new_lines.append(new_line + "\n")

            for field, new_value in patch["fields"].items():
                old_value = "(replaced)"
                if isinstance(new_value, list):
                    new_render = f"[{len(new_value)} trace node(s)]"
                elif isinstance(new_value, dict):
                    new_render = (
                        f"{new_value.get('file')}::{new_value.get('line')}"
                    )
                else:
                    new_render = str(new_value)
                diff_rows.append(
                    {
                        "entry_id": entry_id,
                        "field": field,
                        "before": old_value,
                        "after": new_render,
                        "verify": patch.get("verify", ""),
                    }
                )

            fixes_report.append(
                {
                    "entry_id": entry_id,
                    "commit": entry.get("commit"),
                    "report_id": entry.get("report_id"),
                    "summary": patch["summary"],
                    "verify": patch.get("verify"),
                    "node_counts": {
                        "trace_nodes": len(patch["fields"].get("trace", [])),
                        "entry_point_file": patch["fields"]["entry_point"]["file"],
                        "entry_point_line": patch["fields"]["entry_point"]["line"],
                        "critical_operation_file": patch["fields"]["critical_operation"]["file"],
                        "critical_operation_line": patch["fields"]["critical_operation"]["line"],
                    },
                }
            )

    # Overwrite entries.jsonl with the rewritten lines.
    with ENTRIES_PATH.open("w", encoding="utf-8") as dst:
        dst.writelines(new_lines)

    # Persist field-level diff.
    with OUT_DIFF.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["entry_id", "field", "before", "after", "verify"]
        )
        writer.writeheader()
        writer.writerows(diff_rows)

    OUT_REPORT.parent.mkdir(parents=True, exist_ok=True)
    with OUT_REPORT.open("w", encoding="utf-8") as fh:
        json.dump(
            {
                "generated_by": "scripts/apply_entry_patches.py",
                "schema": "VulnGym entries.jsonl (SCHEMA.md)",
                "fixes": fixes_report,
            },
            fh,
            ensure_ascii=False,
            indent=2,
        )

    print(f"rewrote {len(fixes_report)} entries")
    print(f"diff csv -> {OUT_DIFF}")
    print(f"report  -> {OUT_REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
