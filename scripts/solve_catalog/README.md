# 解法台账重建脚本（2026-11-15）

把历史解出 run 的 `agents.db` item 流离线重建成逐题解法台账，零 token、只读。
产物是 `docs/44-解出题解法台账-20261115.md`。

## 运行顺序（在 VM 上，`/home/rjq` 下）

```bash
scp -P 22 <本目录>/*.py rjq@<vm>:/tmp/
ssh rjq@<vm> "sed -i 's/\r\$//' /tmp/*.py && python3 /tmp/extract_catalog.py"
ssh rjq@<vm> "python3 /tmp/extract_notes.py"      # 依赖上一步的 /home/rjq/solve_catalog.jsonl
ssh rjq@<vm> "python3 /tmp/build_catalog_md.py"   # 依赖 solve_notes.jsonl，输出 /home/rjq/solve-catalog.md
scp rjq@<vm>:/home/rjq/solve-catalog.md ../../docs/44-解出题解法台账-20261115.md
```

## 三个脚本各做什么

| 脚本 | 输入 | 输出 |
|---|---|---|
| `extract_catalog.py` | `/home/rjq/*.jsonl` + `runs/*/strix_runs/*/.state/agents.db` | `~/solve_catalog.jsonl`（题号、墙钟、工具序列、db 路径） |
| `extract_notes.py` | `solve_catalog.jsonl` + 每个 db | `~/solve_notes.jsonl`（`finish_scan` 的 `executive_summary`/`methodology`） |
| `build_catalog_md.py` | `solve_notes.jsonl` + 全部结果行 | `~/solve-catalog.md`（markdown 台账） |

## 两条硬约束（脚本里已实现）

1. **flag 一律脱敏**：正则 `[A-Za-z0-9_.-]{2,40}\{[^{}\s]{4,}\}` → `<FLAG>`。
   `build_catalog_md.py` 还会把结果行里出现的每个真 flag 串回灌成"已知集合"，
   逐个在产物里 grep，命中即 `SystemExit`——不允许带着 flag 生成文档。
2. **靶面域名脱敏**：`https://*.ctfy.run/...` → `<TARGET>`。实例过期即失效，留在文档里没有复用价值。

`item` 是扁平结构（`{"type": "function_call", "name": ...}` / `{"type": "function_call_output"}`），
不是 OpenAI 的嵌套 `content` 数组；按后者的形状解析会得到 0 条工具调用（踩过）。