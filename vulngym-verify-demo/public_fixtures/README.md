# VulnGym Public Test Fixtures

这是 VulnGym 评测器的公开测试集，用于 CI 门禁和基准测试。

## 文件说明

- **entries.jsonl**: 11 条测试样本（10 条正常 + 1 条异常输入）
- **gold.jsonl**: 对应的显式三态金标

## 测试覆盖

### 正常样本（10 条）

1. **entry-00001**: 全部字段正确（XSS）
2. **entry-00002**: entry_point 错误（命令注入）
3. **entry-00003**: entry_point 错误 - 文件不存在（命令注入）
4. **entry-00004**: critical_operation + vuln_category_l2 错误（权限绕过）
5. **entry-00005**: 全部字段正确（SQL 注入）
6. **entry-00006**: commit + vuln_category_l2 不确定（代码注入）
7. **entry-00007**: 全部字段正确（路径遍历）
8. **entry-00008**: vuln_category_l2 不确定（开放重定向）
9. **entry-00009**: 全部字段正确（缓冲区溢出）
10. **entry-00010**: trace 不确定（信息泄露）

### 异常样本（1 条）

- **__invalid_input__bad_json**: 异常输入，期望返回 verdict=uncertain

## 金标格式

显式三态格式，每个字段明确标记为：
- `correct`: 字段正确
- `incorrect`: 字段错误
- `uncertain`: 字段不确定（需要人工复核）

示例：
```json
{
  "entry_id": "entry-00001",
  "verdict": "correct",
  "fields": {
    "entry_point": "correct",
    "critical_operation": "correct",
    "commit": "correct",
    "vuln_ids": "correct",
    "vuln_title": "correct",
    "vuln_category_l1": "correct",
    "vuln_category_l2": "correct",
    "trace": "correct"
  }
}
```

## 使用方法

```bash
cd vulngym-verify-demo
python -m vulngym_verify_demo \
  --entries public_fixtures/entries.jsonl \
  --repo-cache mock_repo \
  --advisories mock_advisories \
  --out /tmp/reports.jsonl \
  --llm mock \
  --bench
```

## 评测指标

- **field_accuracy**: 字段级准确率，目标 ≥ 0.85
- **error_recall**: 错误召回率，目标 ≥ 0.90
- **verdict_accuracy**: 整体判定准确率

运行 `pytest tests/test_eval.py -v` 查看评测测试。
