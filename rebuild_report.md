# VulnGym 链路重建修复报告

涉及条目：`entry-00185` / `entry-00197` / `entry-00290` / `entry-00320` / `entry-00391`

本轮仅修复"整条数据流或调用链语义错位"的 5 个样本，并保持 `SCHEMA.md` 约束不变。当前 `data/entries.jsonl` 已通过两层新鲜验证：

- 本地结构校验：`scripts/verify_patched_entries.py`
- 远程 commit 匹配审计：`scripts/runtime_audit.py --use-remote`

## 0. 验收证据汇总

| entry_id    | project  | commit（短）   | entry_point        | critical_operation    | trace 节点 | verify |
|-------------|----------|----------------|--------------------|-----------------------|-----------:|:------:|
| entry-00185 | n8n      | `538181cb…f4f` | `write.operation.ts:70` | `file-system-helper-functions.ts:61` | 3 | 1 |
| entry-00197 | openclaw | `4320cde9…6a6` | `server.ts:35-36`  | `server.ts:57`        | 5 | 1 |
| entry-00290 | openclaw | `8b5ebff6…09d` | `apply-patch.ts:94`     | `boundary-path.ts:196`     | 5 | 1 |
| entry-00320 | langflow | `e8bbae8e…636` | `files.py:122`     | `local.py:116`        | 5 | 1 |
| entry-00391 | fastmcp  | `c861862a…101` | `director.py:23-28`     | `director.py:194-216`      | 5 | 1 |

合计 **33 个 `{file, line, code}` 节点** 全部经 `runtime_audit.py --use-remote` 在对应 commit 上精确匹配（详见 `debug-b5f720.log`）：

```
overall_failures = 0
  entry-00185: H1=0 H2=0 H3=0 H4=0
  entry-00197: H1=0 H2=0 H3=0 H4=0
  entry-00290: H1=0 H2=0 H3=0 H4=0
  entry-00320: H1=0 H2=0 H3=0 H4=0
  entry-00391: H1=0 H2=0 H3=0 H4=0
```

`scripts/apply_entry_patches.py` 已与 `data/entries.jsonl` 解析后内容一致，可重复运行生成同样的 `entries.jsonl` / `fix_diff.csv` / `examples/report.json`。

---

## 1. entry-00185

项目：`n8n`（仓库 `n8n-io/n8n`，commit `538181cbe32a92616df5e00d7ffaf4d568557f4f`）
问题类型：ReadWriteFile 写入 `.git/` 目录导致 RCE
报告 ID：GHSA-X2MW-7J39-93XQ

修复前问题：

- `entry_point` 落在静态参数声明 `default: false`，不是攻击者输入真正进入执行流的位置。
- `critical_operation` 落在 `resolvePath()` 的闭合括号 `}`，属于明显无关节点。
- `trace` 没有走到真正的写盘调用，整条链路停在无关返回值/语法边界附近。

修复后链路：

- 前置条件：攻击者可控制工作流中的 `fileName` 参数。
- 入口点：`write.operation.ts:70`，用户控制的 `fileName` 首次进入写入执行流。
- 中间传播：`execute()` 收集参数后，`isFilePathBlocked` 仅做 allowlist 包含关系判断。
- 关键缺陷：未对 `.git/` 子路径做专门阻断。
- 最终危险操作：`fsWriteFile(resolvedFilePath, ...)` 将内容真正落盘。

---

## 2. entry-00197

项目：`openclaw`（仓库 `openclaw/openclaw`，commit `4320cde91d9574d65dd240f8b033463cc723d6a6`）
问题类型：sandbox TOCTOU race condition
报告 ID：GHSA-7XMQ-G46G-F8PV

修复前问题：

- 人工备注指出这是多阶段利用，但旧链路没有把"check 阶段"和"use 阶段"清楚展开。
- 旧 trace 的中间节点行号存在错位，部分落在无关代码上。

修复后链路：

- 前置条件：攻击者可请求 `/media/:id`，并能在检查与读取之间替换路径目标。
- 主入口点：`server.ts:35-36`，`req.params.id` 被捕获为外部可控输入。
- 阶段一：`isValidMediaId(id)`（`server.ts:37`）仅做语法层检查。
- 阶段二：`openFileWithinRoot(...)`（`server.ts:42-45`）完成 realpath 检查并返回 handle。
- 阶段三：`Date.now() - stat.mtimeMs > ttlMs`（`server.ts:51`）只做 TTL 判断，不重验边界。
- 最终危险操作：`handle.readFile()`（`server.ts:57`）在 use 阶段读取文件内容。

多阶段说明：

- 该样本不需要新增多个 `entry_point`。
- 通过单入口点加显式 trace，可完整表达"请求进入 → 语法校验 → realpath 检查 → 竞态窗口 → 实际读取"的两阶段语义。
- `trace[0]` 起点直接锚定在 Express 路由注册 + `req.params.id` 捕获；后续 trace 节点覆盖 check/use 配对。

---

## 3. entry-00290

项目：`openclaw`（仓库 `openclaw/openclaw`，commit `8b5ebff67ba16bb68e26a2a0a22ed9556800009d`）
问题类型：悬空符号链接沙箱逃逸
报告 ID：GHSA-QCC4-P59M-P54M

修复前问题：

- 人工备注指出 `critical_operation` 可能是关键检查而非最终 sink。
- 旧链路未清楚区分"fail-open 检查缺陷"和"真正写盘 sink"。
- 旧 trace 存在行号错位，部分节点落在参数行、`break`、闭合括号等无关位置。

修复后链路：

- 前置条件：攻击者可向 `apply_patch` 提交包含悬空符号链接路径的 patch。
- 入口点：`apply-patch.ts:94`，工具执行入口接收外部 patch 输入。
- 中间传播：
  - `applyPatch(input, ...)`（`apply-patch.ts:106-111`）
  - `resolvePatchPath(hunk.path, options)`（`apply-patch.ts:150`）
  - `resolveSymlinkHopPath(lexicalCursor)`（`boundary-path.ts:196`）
- 关键缺陷：当 `realpath` 命中 `ENOENT` 时，`resolveSymlinkHopPath` 走 fail-open 语义，返回仍看似位于沙箱内的词法路径（catch 分支定义见 `boundary-path.ts:487-498`）。
- 最终危险操作：`fileOps.writeFile(target.resolved, hunk.contents)`（`apply-patch.ts:152`）执行越界写入。

多阶段说明：

- 该样本同样不需要多个入口点。
- 但必须同时表达"关键检查点"和"最终 sink"，否则无法解释根因与危害的关系。
- `critical_operation` 保留在 `boundary-path.ts:196` 是有意为之 —— 根因是检查逻辑 fail-open；如果改成 sink，反而把根因信息隐藏。终端 sink 已通过 `trace[4]` 表达。

---

## 4. entry-00320

项目：`langflow`（仓库 `langflow-ai/langflow`，commit `e8bbae8eeb8729abd650f07bfc55957cbdbc1636`）
问题类型：文件上传路径穿越
报告 ID：GHSA-G2J9-7RJ2-GM6C

修复前问题：

- 人工备注指出 entry point 应上移到输入进入处。
- 旧标注把入口放在 `rsplit('.', 1)` 一类字符串处理位置，晚于真实污点进入点。
- 旧行号也曾偏离真实 `file.filename` 接收位置。

修复后链路：

- 前置条件：攻击者可上传带有穿越文件名的 multipart 文件。
- 入口点：`files.py:122`，`file.filename` 直接赋给 `file_name`。
- 中间传播：
  - `rsplit(".", 1)`（`files.py:163-166`）仅拆扩展名，不会过滤路径分隔符。
  - 去重逻辑（`files.py:205-214`）仍保留 `../` 载荷。
- 关键缺陷：`local.py:116` 的 `folder_path / file_name` 将未校验文件名拼接到存储根路径。
- 最终危险操作：`async_open(str(file_path), mode)`（`local.py:120`）按解析后的路径实际写入。

---

## 5. entry-00391

项目：`fastmcp`（仓库 `PrefectHQ/fastmcp`，commit `c861862aededc7294cea5634d77e6926444ca101`）
问题类型：OpenAPIProvider SSRF + 路径穿越
报告 ID：GHSA-VV7Q-7JX5-F767

修复前问题：

- 人工备注指出 `critical_operation` 应更适合定位到拼接处。
- 旧标注停留在 `_build_url` 声明级别，没钉住真正的 `replace(...)` 与 `urljoin(...)`。
- 旧 trace 含有方法声明、空行、无关尾部定义等错位节点。

修复后链路：

- 前置条件：攻击者可控制 OpenAPI 路径参数值，并将 `../` 一类载荷放入 `path_params`。
- 入口点：`director.py:23-28`，`build()` 接收 `flat_args` 与 `base_url`。
- 中间传播：
  - `url = self._build_url(route.path, path_params, base_url)`（`director.py:53-54`）
  - `_build_url` 中遍历 `path_params`（`director.py:208-213`）
  - `url_path = url_path.replace(...)`（`director.py:213`，单独再列一次以锚定 splice 单点）
- 关键缺陷：路径参数直接文本替换进入 URL 模板，未做编码。
- 最终危险操作：`urljoin(...)`（`director.py:215-216`）归一化路径，折叠 `../`，得到越界 URL。

---

## 6. 验收对照

全部由 `runtime_audit.py --use-remote` + `verify_patched_entries.py` 自动复核：

- 每个修复后的 `{file, line, code}` 在对应 commit 上精确匹配：H1=0 / 33 节点。
- `desc` 可解释节点在链路中的作用：H3=0；verify 对每条 entry 的 `entry_point` / `critical_operation` / 全部 trace 节点检查 desc 非空。
- 多阶段样本已显式写出前置阶段与主触发阶段：entry-00197 覆盖 check/use 两阶段；entry-00290 的 `critical_operation` desc 标注 check-vs-sink 区别并把 sink 放到 trace 末端。
- 纯日志、无关返回值、静态声明、闭合括号等明显无关 trace 节点已删除或替换：H4=0。
- 修复后数据仍满足 `SCHEMA.md` 基础约束：H3=0 全条目 schema clean。
- `manual_review.csv` 为空表头，本轮无保留未决阻塞项。