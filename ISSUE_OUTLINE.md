# VulnGym T1 Issue 总纲（独立审查修订版）

## 1. 决策基线

- 目标仓库：`perhaps468/VulnGym`（当前 `origin`），集成目标为默认分支 `main`。
- 实现范围：以 `vulngym-verify-demo/` 为最终可运行交付物；根目录 `SCHEMA.md`、数据集和现有评测器保持兼容，仅在必要时扩展。
- 交付目标：完成题目 T1 Standard 档；Bonus 为独立、非阻塞增强项。
- 数据协议：训练集/公开测试 fixture、gold 和运行脚本可入仓库；隐藏测试集及金标不入仓库，只提交外部运行汇总。
- LLM 协议：提供商无关适配层，支持 Qwen/DeepSeek/GLM；默认离线 fixture/mock 可复现；真实 LLM 失败只能降级为 `uncertain`，不得伪造正确证据；API key 不得入库。
- GitHub 流程：总纲经独立 Agent 审查并由用户确认后，才创建父 Issue、子 Issue 和原生 `blocked by`/`blocks` 关系。

## 2. 成功标准（父 Issue 关闭门槛）

必须全部满足：

1. 字段级准确率 `>= 0.85`。
2. 错误条目找错召回率 `>= 0.90`。
3. 抽查 20 条报告时，证据可追溯且合理率 `>= 80%`。
4. 缺失字段、坏 commit、公告缓存缺失/404、目标文件不存在、LLM 超时/限流/非法 JSON 等异常不崩溃，并按信息不足输出 `uncertain`（确定性事实明确失败时可输出 `incorrect`，证据必须说明原因）。
5. JSONL 批处理可运行，输出符合冻结的 `VerificationReport` 契约。
6. README、1~3 页设计文档、公开测试集输出、5 分钟演示材料齐全且可复现。
7. 集成 Agent 按依赖顺序审阅、测试并合并所有 Standard PR；最终端到端验收记录已提交。

证据抽查必须使用固定 seed 的可复现抽样（默认 seed `20260902`，记录抽中的 20 个 `entry_id`），按“来源可定位、代码/公告内容支持结论、未编造、置信度与证据一致”四项 rubric 判定；抽查结果和未通过项写入验收报告。每条报告整体至少覆盖公告与源码两类来源；单字段只需记录适合该字段的来源，不要求每个字段同时引用两类来源。

## 3. 当前代码基线与已知缺口

当前原型已提供：

- `vulngym_verify_demo.tools.VulnGymTools`：公告读取、commit checkout、文件行读取、grep、git log。
- `field_checkers.py`：8 个核心字段检查器和 `check_all_fields`。
- `llm_client.py`：Qwen/DeepSeek/GLM、`SafeLLMClient`、`ResilientLLMClient`、脚本 Mock。
- `agent.py`：规划 -> 工具/LLM -> self-check 闭环。
- `cli.py`：JSONL 输入/输出、`--gold`、`--bench`、verbose。
- `eval.py`：字段准确率、错误召回、verdict 和字段分解。
- `mock_data/`、`mock_repo/`、`mock_advisories/` 和已有截图/日志。

需要在 Issue 中明确修正或验收的缺口：

- 输入 schema/类型/枚举/必填字段没有统一前置校验；单条坏记录不能拖垮批处理。
- 公告缓存字段与真实 GHSA/CVE 数据的映射、版本范围和修复 commit 语义、404/损坏 JSON 语义需要冻结。
- `vuln_ids`、`vuln_title`、分类和 trace 整体判断需有可审计 prompt/结构化解析；LLM 输出必须校验 status/confidence/evidence。
- self-check 当前只返回意见，需确保不覆盖工具确认的事实，并在不成功时保留可追溯状态。
- CLI 的配置、退出码、日志、并发/超时策略和路径解析需要可复现并覆盖 Windows/Linux。
- 评测器需明确字段集合、gold 推断规则、异常样本计分和隐藏集汇总格式。
- 当前仓库缺少统一 pytest 配置、CI 门禁和 Standard 交付文档索引。

对本轮审查意见的客观结论：P1 的 commit 版本语义、缓存后端/并发模型、坏输入输出、未知字段兼容性和共享 JSON 结构属于真实契约缺口，已纳入 I1~I3/I6；证据“每字段双来源”属于过严表述，已改为报告级双来源；Standard 引入并发属于不必要的风险扩张，已降为 Bonus/后续 Issue。现有代码确实是顺序处理、快照式缓存，且 `iter_jsonl` 对坏 JSON 会直接抛错；这些行为由对应 Issue 明确替换或冻结。

## 4. 冻结共享接口

### 4.1 VerificationReport

每条输入记录输出一行 JSON：

```json
{
  "report_id": "...",
  "entry_id": "...",
  "verdict": "correct|incorrect|uncertain",
  "fields": {
    "entry_point": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "critical_operation": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "commit": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "vuln_ids": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "vuln_title": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "vuln_category_l1": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "vuln_category_l2": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []},
    "trace": {"status": "correct|incorrect|uncertain", "confidence": 0.0, "evidence": "...", "evidence_refs": []}
  },
  "summary": "...",
  "self_check": {"status": "completed", "agree": true, "comment": "...", "checked_fields": []},
  "plan": {},
  "tool_trace": []
}
```

`report_id`、`entry_id`、`verdict`、8 个字段及其三态状态为必填；每个字段对象必须有 `status`、`confidence`、`evidence`、`evidence_refs`，其中引用格式为 `{source: advisory|repository|git, locator: string, quote: string}`，无证据时 `evidence_refs=[]` 且 evidence 必须解释缺口。`summary`、`self_check`、`plan` 必须存在于 Standard 交付。坏输入行也必须生成报告：使用稳定占位符 `__invalid_input__:<line_no>` 同时填充缺失的 `report_id`/`entry_id`，并增加可选 `input_error`（`line_no`、`kind`、`message`）。`tool_trace` 为运行时审计字段，至少记录实际调用的 3 类工具；不能只记录计划中的工具名。允许新增符合 SCHEMA 前向兼容规则的可选字段，不得加入 SCHEMA 明确禁止的内部字段或改名/改变既有语义。

最小 JSON 结构如下（唯一规范文件由 I1 放在 `vulngym-verify-demo/vulngym_verify_demo/report_schema.json`）：

```json
{
  "plan": {"version": "1", "tools_planned": ["read_advisory", "checkout", "read_file_lines"], "fields_planned": ["entry_point", "critical_operation"]},
  "self_check": {"status": "completed|skipped|failed", "agree": true, "comment": "...", "checked_fields": ["entry_point"]},
  "tool_trace": [{"seq": 1, "tool": "read_advisory", "input": {"report_id": "..."}, "ok": true, "error": null, "evidence_refs": ["fields.vuln_ids.evidence"]}]
}
```

`self_check.agree` 在 `status=failed|skipped` 时为 `false`；`tool_trace.input` 只允许脱敏后的摘要，`evidence_refs` 使用 JSON 路径，不能记录 API key 或完整本地绝对路径。上述键名、枚举和类型由 I1 固化为唯一 JSON Schema 文件。

### 4.2 Python 边界

冻结并向后兼容以下名称与职责：`VulnGymTools`、`BaseLLMClient`、`ResilientLLMClient`、`check_all_fields`、`verify_entry`、`verify_entries`、`evaluate`。

确定性工具结果不得被 LLM 覆盖。LLM 只负责语义字段和整体合理性；任何不可解析/不可用结果必须转成结构化 `uncertain`，并保留原因。结构化响应必须校验 `status` 枚举、`confidence` 在 `[0,1]`、`evidence` 非空并脱敏；真实 LLM 失败时禁止用关键词/启发式回退为 `correct`。

## 5. Issue DAG 与工作边界

编号在 GitHub 创建后回填；下列 `I1`~`I11` 是逻辑编号。

### I1 — 基线、输入校验与输出契约（Standard）

- 范围：按根目录 `SCHEMA.md` 校验全部必填字段（包括 `origin`、`verify` 等）及嵌套 `file/line/code`、line>0/合法 range、枚举和类型；允许未知的未来可选顶层字段，拒绝 SCHEMA 明确禁止的内部字段；定义错误模型、`VerificationReport` 序列化和坏输入报告协议；补齐最小 fixture。
- 文件所有权：`vulngym-verify-demo/vulngym_verify_demo/schema*.py`、`models*.py`、根目录 `tests/test_schema.py` 和契约文档。
- 依赖：无。被 I2、I3、I4、I5、I6、I7 阻塞。
- 验收：合法/非法/缺失/未知可选字段/禁止内部字段测试；单条坏记录产生结构化 uncertain，不中断批处理；坏 JSON 行使用 `__invalid_input__:<line_no>` 稳定 ID；契约样例可 JSON round-trip。

### I2 — 本地公告与仓库工具层（Standard）

- 范围：稳定 `VulnGymTools`；冻结 Standard 缓存模型为预生成 `<project>/<commit>/` 只读快照，无网络、并发只读安全；`repo_url` 通过去除 `https://github.com/`、`.git` 并规范化 owner/name 后映射到 manifest 中的唯一 `project` key，禁止仅凭 basename 产生碰撞。manifest 每项至少包含 `{repo_url, project, commit, version, role}`，其中 `role` 为 `vulnerable|fixed|unknown`，供 I3 判断版本和修复 commit 关系；可选 Git backend 仅作为后续扩展，必须在独立工作树/临时 checkout 中读取，禁止共享可变工作树；绝对路径与 `..` 穿越拒绝；公告 404、权限错误、损坏 JSON 和坏 commit 均返回不泄漏敏感路径的 `ToolResult(ok=false)`，不得抛未处理异常。
- 文件所有权：`vulngym-verify-demo/vulngym_verify_demo/tools.py`、`vulngym-verify-demo/mock_repo/manifest.json`、根目录 `tests/test_tools.py`、fixture 生成脚本。
- 依赖：I1。被 I3、I4、I5、I6 阻塞。
- 验收：mock 与 manifest/目录结构测试；路径穿越被拒绝；无网络运行；每类失败可预测且不抛出未处理异常。

### I3 — 确定性字段检查器（Standard）

- 范围：entry point、critical operation、commit、trace 节点的 checkout 后代码/行号/文件存在性、容错窗口和证据；不得由 LLM 改写事实结果。
- 文件所有权：`field_checkers.py` 中确定性部分及根目录 `tests/test_field_checkers.py`；不得修改 `check_all_fields` 汇总器。
- 依赖：I1、I2。可与 I4 并行；被 I5、I7 阻塞。
- 验收：正确、行漂移、代码不匹配、文件缺失、commit 不存在、空 trace 等 fixture；commit 判定必须分层：格式有效 -> 缓存/仓库中可解析 -> 与公告受影响版本范围相容；只有公告提供可验证范围且 commit 可映射时才能判 `correct`，无法映射版本或公告仅给模糊范围时判 `uncertain`。若公告提供修复 commit/patch，必须区分修复 commit 与漏洞版本 commit，不能把修复 commit 当作引入 commit；状态、置信度和证据稳定。

### I4 — LLM 语义判定与安全降级（Standard）

- 范围：Qwen/DeepSeek/GLM 适配、结构化响应解析、prompt 版本化、Safe/Resilient fallback；覆盖 title、category、vuln_ids 语义和 trace 整体判断。
- 文件所有权：`llm_client.py`、语义 prompt/解析模块及根目录 `tests/test_llm.py`。
- 依赖：I1、I2。可与 I3 并行；被 I5、I7 阻塞。
- 验收：mock fixture 可复现；非法 JSON、超时、HTTP 错误、无 key 均输出 semantic `uncertain`，不得通过关键词启发式判 `correct`；响应 schema、证据非空和脱敏校验有效；API key 不出现在日志/报告。

### I5 — Agent 规划、工具调用与 self-check（Standard）

- 范围：在 I3/I4 合并后编排两者，保证“规划 -> 至少 3 类工具 -> 反思”闭环；运行时记录 `tool_trace`；self-check 只提出修正建议，不覆盖确定性证据；保留 plan/self-check 审计信息。I5 不改变 I3/I4 的核心实现文件，仅在其合并后接入适配层。
- 文件所有权：`agent.py` 中编排与汇总部分、`tests/test_agent.py`；只能在 I3/I4 合并后修改 `check_all_fields` 调用边界，不改 I3 的确定性检查逻辑。
- 依赖：I1、I2、I3、I4。完成后解除 I6、I7、I9、I10、I11。
- 验收：每条报告包含符合 I1 schema 的 plan/self-check/tool_trace；运行时确实调用至少 3 类工具且记录证据引用；self-check 失败不阻塞；verdict 汇总遵循三态规则；每条报告整体覆盖公告与源码两类来源，字段按其适用来源引用证据。

### I6 — 批处理 CLI、配置、日志与可复现运行（Standard）

- 范围：JSONL 顺序流式处理、单条错误隔离、路径/环境变量配置、退出码、日志脱敏和超时；保持现有命令兼容。Standard 不引入并发；并发、重试和共享客户端线程安全作为 Bonus/后续 Issue，除非另行冻结隔离、顺序和超时协议。
- 文件所有权：`cli.py`、运行脚本、`tests/test_cli.py`；不得修改 `README.md`（由 I8 统一维护）、`tests/test_eval.py`、CI 配置或评测 fixture。
- 依赖：I1、I2、I5。可与 I7 并行；被 I8 阻塞。
- 验收：mock/安全 fallback smoke；空行、坏 JSON、缺字段混合输入均各自产生稳定 `__invalid_input__:<line_no>` 报告并继续处理；Windows/Linux 命令示例；非零退出码仅用于不可恢复输入/配置错误。

### I7 — 评测器、公开 fixture、指标与鲁棒性测试（Standard）

- 范围：扩展 `evaluate` 与 `format_metrics`，固定 8 字段、支持逐字段三态显式 gold 与现有兼容格式，定义异常样本、缺失报告计分；补 pytest、CI 门禁、公开测试输出。
- 文件所有权：`eval.py`、根目录 `tests/test_eval.py`、`tests/test_robustness.py`、CI 配置、公开 fixture/报告；不得修改 `tests/test_cli.py`。所有 pytest 从仓库根目录运行，使用显式 `pythonpath`/包安装方式导入 `vulngym_verify_demo`。
- 依赖：I1、I2、I3、I4、I5。可与 I6 并行；被 I8 阻塞。
- 验收：字段准确率、错误召回、verdict、字段 breakdown 与题目阈值一致；显式 gold、兼容 gold、缺失报告和异常样本规则均有测试；回归测试覆盖所有鲁棒性场景；CI 可离线通过。

### I8 — Standard 文档、公开输出与演示材料（Standard）

- 范围：README、1~3 页设计文档（架构图/工具/prompt/坑）、公开测试 JSONL、5 分钟演示脚本/截图；记录隐藏集汇总模板。
- 文件所有权：`vulngym-verify-demo/README.md`、`docs/`、`demo/`、公开输出和索引。
- 依赖：I6、I7。父 Issue 的 Standard 完成闸门。
- 验收：新环境按 README 一键运行；文档命令与实现一致；演示覆盖正常路径、异常 fallback、指标输出；无 key/隐藏金标泄露。

### I9 — Bonus：系统性错误识别与归因

- 范围：跨 entry 聚合错误模式、工具/模型偏差统计、归因报告。
- 文件所有权：新增 `bonus/error_attribution/` 模块、报告模板和专属测试，不直接改 I3/I4 核心实现或共享索引。
- 依赖：I5、I7；非阻塞，可与 I10/I11 并行。
- 验收：对可控注入错误输出稳定归因，包含样本数、影响字段和证据链接。

### I10 — Bonus：错误字段修正建议

- 范围：在不改变 `status` 的前提下增加可选 `suggested_value`/`suggestion_evidence`，对 line、category、title 等给出可审计建议。
- 文件所有权：新增 `bonus/suggestions/` 模块和专属 schema 可选字段测试，不直接修改 I1 核心模型；通过可选扩展字段接入。
- 依赖：I5、I7；非阻塞，可与 I9/I11 并行。
- 验收：建议字段可选、向后兼容；无证据时不猜测并输出 uncertain/needs_manual_review。

### I11 — Bonus：多语言代码适配

- 范围：针对 Python/JS/Go/Java 的行读取、代码归一化、grep/语法辅助策略；不得引入被检查仓库内陌生二进制执行。
- 文件所有权：新增 `language/` 适配模块和跨语言 fixture/测试，不修改 I3 核心接口签名。
- 依赖：I2、I3、I5；非阻塞，可与 I9/I10 并行。
- 验收：四种语言 fixture 均能定位节点并给出证据；不支持语言安全降级 uncertain。

## 6. 依赖、并行和 Agent 分配规则

推荐拓扑：`I1 -> I2 -> (I3 || I4) -> I5 -> (I6 || I7) -> I8`；`I9/I10/I11` 在 I5（并建议 I7）完成后并行。

只有同时满足以下条件才分配独立 Codex Agent/worktree/分支：

- 所有 `blocked by` Issue 已关闭或明确解除；
- 目标文件所有权与其他运行中 Issue 不重叠；
- 分支从最新集成目标分支创建，命名 `codex/issue-<number>-<short-name>`；
- Agent 必须提交代码、测试、运行结果和 PR；不得直接合并。

集成 Agent 按 DAG 顺序审阅 PR：先契约/工具，再字段与 LLM，再编排，再 CLI/评测，最后文档；每次合并前运行相关 pytest 和 CLI smoke，合并后运行全量离线测试。

## 7. GitHub Issue/PR 模板要求

父 Issue 必须包含：目标、范围、成功标准、Issue 清单、依赖图、共享接口、并行分配规则、Standard/Bonus 闸门、隐藏集汇总位置和关闭清单。

每个子 Issue 必须包含：背景、非目标、文件所有权、输入/输出契约、`Blocked by`/`Blocks`、测试命令、验收标准、交付 PR 要求、风险与回滚点。

PR 必须链接对应子 Issue，说明变更文件、测试命令与结果、契约兼容性、是否引入新依赖/凭据；集成 Agent 在 PR 中记录审查结论和合并依据。

## 8. 执行前检查（不改变总纲）

- 执行 GitHub 写操作前运行 `gh auth status`，确认 `perhaps468/VulnGym` Issue/PR/依赖关系写权限。
- 创建 Issue 前确认公开 fixture 的最终数量和隐藏集汇总报告路径；默认使用 `reports/hidden_eval_summary.json`，不提交隐藏样本/金标。
- 若 GitHub 原生依赖关系 API 不可用，保留正文中的双向 `Blocked by`/`Blocks` 引用，并在父 Issue 记录限制。
