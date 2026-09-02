# vulngym-verify-demo

VulnGym 字段级数据验证 Demo — 犀牛鸟实战考题（T1）。

本 Demo 实现了一个可运行、可截图、可读懂的小型工程，用于：
- 演示对 VulnGym `entries.jsonl` 的字段级自动化审核能力
- 验证 Agent "规划 → 工具调用 → 反思" 闭环
- 在 mock 数据上跑出对照结果，方便截图贴到申请书中

## 运行

```bash
# 1) 进入项目根目录
cd vulngym-verify-demo

# 2) 跑 mock 模式（不依赖网络/API key）
python -m vulngym_verify_demo \
    --entries mock_data/entries.jsonl \
    --repo-cache mock_repo \
    --advisories mock_advisories \
    --out out/reports.jsonl \
    --llm mock \
    --verbose

# 3) 跑真实 Qwen / GLM（先 export 环境变量）
#    Windows PowerShell:
#    $env:QWEN_API_KEY="sk-..."
#    $env:QWEN_BASE_URL="https://dashscope.aliyuncs.com/compatible-mode/v1"
#    $env:QWEN_MODEL="qwen-turbo"
python -m vulngym_verify_demo \
    --entries mock_data/entries.jsonl \
    --repo-cache mock_repo \
    --advisories mock_advisories \
    --out out/reports_qwen.jsonl \
    --llm qwen \
    --verbose

#    GLM（智谱）：
#    $env:GLM_API_KEY="..."
#    $env:GLM_BASE_URL="https://open.bigmodel.cn/api/paas/v4"
#    $env:GLM_MODEL="glm-4-flash"
python -m vulngym_verify_demo \
    --entries mock_data/entries.jsonl \
    --repo-cache mock_repo \
    --advisories mock_advisories \
    --out out/reports_glm.jsonl \
    --llm glm \
    --verbose

#    DeepSeek：
#    $env:DEEPSEEK_API_KEY="..."
#    $env:DEEPSEEK_BASE_URL="https://api.deepseek.com"
#    $env:DEEPSEEK_MODEL="deepseek-v4-pro"
python -m vulngym_verify_demo \
    --entries mock_data/entries.jsonl \
    --repo-cache mock_repo \
    --advisories mock_advisories \
    --out out/reports_deepseek.jsonl \
    --llm deepseek \
    --verbose
```

## 目录

```
vulngym-verify-demo/
├── README.md
├── mock_data/                手写 mock 样本（含故意的脏数据）
│   └── entries.jsonl
├── mock_repo/                mock 仓库缓存 (<project>/<commit>/<file>)
├── mock_advisories/          mock 公告缓存 (one GHSA -> one .json)
├── out/                      跑出的报告 JSONL
└── src/
    ├── tools.py              智能体工具集（read_advisory/checkout/read_file_lines/grep_code/git_log）
    ├── llm_client.py         Qwen 客户端 + Mock 兜底
    ├── field_checkers.py     单字段三态判定
    ├── agent.py              规划 -> 工具调用 -> 反思 闭环
    └── cli.py                命令行入口
```

## Mock 数据设计

`mock_data/entries.jsonl` 内含 4 条 entry，故意包含以下"数据脏"：

| entry_id        | 故意改错的字段                                  | 设计 verdict | 实际 verdict（mock 跑出） |
|-----------------|----------------------------------------------|--------------|--------------------------|
| entry-00001     | 无（全对）                                    | correct      | correct                  |
| entry-00002     | critical_operation.line 写 200（实际 250）    | incorrect    | incorrect (critical_operation) |
| entry-00003     | entry_point.file 指向不存在的路径             | incorrect    | incorrect (entry_point)  |
| entry-00004     | vuln_category_l2 错位（"权限提升" vs "权限绕过"） | incorrect | incorrect (vuln_category_l2) |

跑出来的 reports.jsonl 应该 1 条 correct + 3 条 incorrect，与设计完全一致。

## 字段级三态

每个字段输出 `{status, confidence, evidence}`：
- `correct`   高置信度匹配
- `incorrect` 高置信度不匹配（标注数据脏）
- `uncertain` 信息不足，需要补充

整体 verdict 规则：任一字段 incorrect → incorrect；全部 correct → correct；其余 uncertain。