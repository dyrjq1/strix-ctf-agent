# 要把关的问题（按优先级，2026-11-05）

评审目标：初选赛 11-15（10:00–20:00 UTC+8，约 10 天后）前，这个 agent 的方向和工程质量有没有致命风险。请按此优先级给意见，每条给「通过 / 有保留通过 / 打回」三选一 + 理由。

## P0（赛前几天就会踩的）

1. **5xx 重试梯太短**：strix 内建 5 次重试（2/4/8/16/32s ≈ 62s 窗口）。实测 11-04 平台网关断供约 5+ 分钟，4 个 run 直接报废（归档证据：stdout 里的 overloaded_error 链）。初选赛 10h 窗口内网关抖动概率不低。问题：把 5xx/RemoteProtocolError 的重试梯拉长到分钟级（受墙钟约束），方案上有什么坑？（注意红线：不许单独调预算，重试梯属于韧性，依附「网关抖动真实发生」的实测物理依据）
2. **BYOK key 平台侧中途失效**（11-04 22:09 实发，重填后恢复）：我们能做什么检测/自愈？还是纯平台侧风险、只能赛前人工检查？
3. **单实例 10h 串行轮转**：任何一题的 run 挂死（不触发墙钟的路径）都会烧掉后续所有时间。现有的 deadline_guard + SIGALRM 看门狗组合有没有漏网路径？

## P1（竞速开闸链路，正在走）

4. **审 02-pending-review.diff**：这是 Codex 对 #3 parallel-race 与 #4b 结构化解信号交互的修复（未经我验收）。重点：child 的 exec_command 是否也走 exec observer 结构化判定（b 场景）；child 赢面 → root 停止 + result.json 落盘链路（c 场景）；反例（placeholder flag / 证据不支持）不触发。
5. **竞速开闸决策**：方差批实测——070 一路 162s 解出、另一路 24min 耗尽（同代码同题）；005/033/071 双采样皆败。我的结论：竞速对「单点方向可解但易选错」的题有真实收益（070 型），对「根本不知道方向」的题无效（005/033/071 型）。开闸参数建议：默认关 → 高难度题（difficulty=hard）自动开 2 路。这个判断对吗？有没有更便宜的替代（如更聪明的方向选择提示）？

## P2（架构债）

6. **防幻觉机制强度**：vendor strix 的证据链哲学（evidence 必须非空、http_exchange_ids 对真代理历史核验）被我们部分替换成 SuccessLedger 结构化判定。读 `success_stop.py` 的 check_verdict/answer_verdict（四重校验）和 `finish_guard.py` 的 PoE 放行，有没有比 vendor 原设计更弱的环节？
7. **071 采样 B 输出失控**（151k token 单 run）：这暴露了什么守卫缺口？推理输出无上限时的止损机制？
8. 正式赛 11-21 出题窗口（authoring）需要 agent 出题能力，目前空白——初选赛后再投入，但如果有低成本准备动作（比如先读 get_authoring_template 的 schema），值得现在做吗？

## 请勿投入精力的方向

- 不需要评审 vendor/src/strix 全量代码（只需要 `vendor/src/strix/tools/reporting/tool.py` 的证据链哲学作为对照）
- 不要建议引入需要外网的运行时工具（赛制 deny）
- 不要建议调大预算参数（纪律：预算改动必须依附能力改动）
- 不要基于练习赛成绩外推正式赛（正式赛 challenges_withheld=true）
