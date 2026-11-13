# 审查包入口（给 Claude 评审，2026-11-05）

你是被请来给一个 CTF 自主解题 agent 把关的评审。这个包的目标：**用最少的阅读量拿到最全的上下文**。请严格按下面的顺序读，不要跳去读全量仓库。

## 阅读顺序（共约 5 个文件 + 定点代码）

1. **01-progress-digest.md**（本包）——演进主线 + 最新实测数据。2 分钟。**一切数字以此为准**。
2. **CLAUDE.md**（本包）——项目的权威简报：赛制硬约束、工具清单、工作原则（防过拟合四红线、八步流程）、架构地图。但注意下面的「修正覆盖表」。
3. **03-open-questions.md**（本包）——要你把关的 8 个问题，按 P0/P1/P2 排序。
4. **02-pending-review.diff**（本包）——未验收的竞速交互修复 diff，对应问题 4。
5. 定点代码（在 C:\Users\rjq\Downloads\strix-ctf-agent，只读这些，别的不用）：
   - `src/ctf_strix/success_stop.py` 的 `check_verdict`/`answer_verdict`（约 :90-144）+ `install_exec_observer`（:327 起）
   - `src/ctf_strix/finish_guard.py`（全部，短）
   - `src/ctf_strix/parallel.py`（全部，519 行，含未提交修改）
   - `vendor/src/strix/tools/reporting/tool.py`（仅看证据链哲学作对照，不要读其他 vendor 代码）
   - 如需看竞速提示：`src/ctf_strix/prompt.py` 的 `_RACE` 段（:177-200 附近）

## CLAUDE.md 修正覆盖表（该文件是 11-03 拷贝，以下数字已过时）

| CLAUDE.md 写的 | 现状（以 01-digest 为准） |
|---|---|
| 全量测试 506 passed | **684 passed, 4 skipped**（+Codex 新增测试待验收后更高） |
| 镜像 v2 已构建、注册 v1 | **v5 已注册在平台**（v3/v4/v5 演进见 digest） |
| CTFARENA 已测 48/115 | **67/115 全部已测，agent 解出 50** |
| 台账最新 §4.61 | **§4.68** |
| 「暂不做多 agent 并发」 | 竞速（题内 ≤2 子 agent）已实现待开闸，见 digest §五 |
| 诊断批在跑 | 已完成，被 11-04 网关断供事故部分打断，归因完毕 |

## 禁读清单（省你 token 也防泄密）

- `vendor/src/strix/` 除上述一个文件外全部不读（60 万行级，与把关无关）
- `reference/`、`traces/`（含真实 flag，不要复制进任何产出）
- `docs/` 下除台账外不必读（台账也只需 digest 版，除非你要核对某个决策的原始记录）
- `ctfwork/`（临时脚本堆）

## 产出要求

对 03-open-questions.md 的 8 个问题逐条给：通过 / 有保留通过 / 打回 + 理由 + （如打回）你认为对的做法。发现我们没问到的风险，单列一节。总篇幅 ≤60 行，结论先行。不确定的地方明说「无法从现有材料判断」，不要猜。
