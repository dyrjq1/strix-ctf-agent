# 已停用代码存档

这里存放**不再参与任何跑批或运行时**的历史代码，保留是为了可追溯与回滚，
不要从 `scripts/` 或 `src/` 引用。

| 文件 | 停用日期 | 原因 | 知识存档 |
|---|---|---|---|
| `qa_eval.py` | 2026-10-31 | 官方 QA#26/#31 明确正式赛为 CTF 六类解题赛制，没有选择题 | `docs/13-选择题通道设计.md` |

恢复方式（仅在确需复现历史实验时）：

```powershell
Move-Item -LiteralPath archive/qa_eval.py -Destination scripts/qa_eval.py
```
