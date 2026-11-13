# 开发窗口交接包 — 2026-11-05 晚

> 读者：新开的 Claude Code 窗口（开发统筹角色），在 `C:\Users\rjq\Downloads\strix-ctf-agent` 启动。
> 你先读 CLAUDE.md（常青简报），再读本文件（此刻进行到哪）。两者冲突以 CLAUDE.md 和台账为准。
> 姊妹窗口（作战调度）跑在 `C:\Users\rjq\Downloads\ctf-collab`，启动简报 `COMBAT-BRIEF.md`。两窗口通过 GitHub issue 与队长互通，互不接管领地。

## 1. 今天（11-05）完成的事

| 项 | 状态 | 证据 |
|---|---|---|
| task7 错误分流器 | ✅ commit `8e5659d`，已推送，台账 §4.70 | 710 passed, 4 skipped（统筹者亲跑复现） |
| Codex 工具箱 | ✅ 验收通过 | `C:\Users\rjq\Downloads\ctf-toolbox\`（1.59GB，TOOLBOX.md + verify.log + provenance） |
| 协同演练（SAMPLE） | ✅ 5 分支全验 | 010/002/006 三题真实 solved；细节见 issue #2/#3/#4 与 `docs/34-协同作战编排.md` §6 |
| 阿里云 key | ✅ 已定位 | 本地跑题用（dashscope 端点）；平台 eval 批用不了（模型-端点映射冲突，memory 有全表） |
| 诱饵附件教训 | ✅ 入 memory | `memory/decoy-attachments.md`（per-team-artifact 必先起实例拉真附件） |

## 2. P0 链（评审整合后的顺序，从上往下做）

1. ~~错误分流器~~ ✅（§4.70）
2. **task8 看门狗加固** ← **下一个。任务单已写好：`ctfwork/task8-watchdog-brief.txt`**，直接派 Codex（加 `--skip-git-repo-check` 若目录非 git）。要求：守护线程双级（软窗口复用 error_policy.WALL_RESERVE_SECONDS，硬路径 os._exit 前写兜底 result.json）；验收场景 a-e 在任务单里；全量 >= 710 passed。
3. 证据链加固（Q6）：EvidenceLedger.observe_output 对任何工具输出的 FLAG_RE 都算数（自回显/诱饵风险）——flag 路径 finish 需平台 verdict 或排除自回显来源
4. 输出 token 止损（Q7）：071 sample B 输出 151k tokens 无上限——接 usage_meter 加输出硬顶
5. v6 镜像 + 三路径终局冒烟（正常解出 / PoE verify_exploit / 干净失败）

## 3. 演练带出的新债（写入 P0 链考虑）

- **PoE 题在 batch_eval 判 FAILED**：agent 攻击成功但无 flag 可交（SAMPLE-006 实证：run.log 有持久化 defacement，finish guard 拒了 3 次，轮尽判负）。#4b 修的是 agent 入口，VM 的 batch_eval 链路没这逻辑。协同模式可由调度者 verify_exploit 收尾（今天就是这么解的），但智能体赛道正式赛遇到 PoE 题会直接丢分——**初选赛前必须决定：给 batch_eval/agent 加 verify_exploit 调用，还是确认正式赛无 PoE 题**（11-07 规则出来核对）。
- VM 代码停在 commit `616ca78`（11-03），落后本地 `8e5659d` 一大截（#4b/#5/error_policy 都没上 VM）。下个同步窗把 src/ 推上去。
- VM token 文件已就位：`/home/rjq/.pftoken`（平台）、`/home/rjq/.llmkey`（阿里云 dashscope，环境变量照 `ctfwork/vm_drill_s006b.sh` 抄）。

## 4. 当前工作区状态

- git：main @ `8e5659d`，工作区干净（未跟踪：docs/31、plan.diag3.json、review-package-20261105/、HANDOFF 本文件——都是有意保留）
- 远程推送：用 IP 直连绕 DNS 污染（`git -c http.curloptResolve=github.com:443:140.82.112.4 push`，可用 IP 见 memory/parallel-tracks 或逐个试 140.82.112.4/20.27.177.113）
- 测试基线：**710 passed, 4 skipped**（`--basetemp` 纪律见 CLAUDE.md §8.1）
- 台账最新：§4.70。追加用临时文件 + os.replace + 锚点断言（脚本模板 `ctfwork/append_ledger_470.py`）
- Codex 派单命令模板：`cmd /c "codex exec --skip-git-repo-check -C <dir> -o out.md - < brief.txt > log.txt 2>&1"`，**绝不传 `-s`**；非 git 目录必加 `--skip-git-repo-check`
- 后台任务：无在跑。内存余量 ~2GB 时别双开 codex

## 5. 待办排序（11-15 初选赛倒计时 10 天）

1. 派 task8（任务单就绪，见 §2）
2. PoE 决策（§3 第一条）——11-07 规则发布后定
3. VM 代码同步（§3 第二条）
4. 台账补记：今天三场演练 + SAMPLE 三题解出（协同侧，不算 agent 成绩，但要留痕）
5. 诊断批 3 题（CTFARENA-043/047 + CYBENCH-001）结果若 Codex 之前跑过，查看 VM ~/results*.jsonl
6. P16~P19k + error_policy 的真题迁移验证批（未参与改动的题）
7. 提醒队长：两赛道报名（智能体 11-13 截止；清华场人机协同同日截止且需审核）+ GitHub repo 私有化（issue 里有真实 flag，**公网裸奔中，队长已知待办**）
8. BYOK key 状态赛前检查（11-04 掉过 key）

## 6. 关键人物/通道

- 队长：直接对话。授权范围见 memory（八步回路全自动 + 夜间 flag 解出即提交）
- WorkBuddy：GitHub issue 黑板（repo dyrjq1/strix-ctf-agent），协议见 docs/34 §3；它有 30s 自动唤醒
- CodeBuddy：**已顶替 WorkBuddy 的解题工位**（2026-11-05 用户拍板）。接入方式、权限坑、测试记录见 `HANDOFF-CODEBUDDY-20261105.md`（仓库根，未提交）。核心：批处理文件 + `--allowedTools` **逗号分隔**，settings.json 在 `-p` 模式下无效
- 作战窗口：`C:\Users\rjq\Downloads\ctf-collab`（COMBAT-BRIEF.md）；它发现 agent bug 会开 issue 转给你
- 外部评审：review-package-20261105/ 的 8 问裁决已全部整合进 P0 链；Q5（竞速开阀）已打回推迟到初选赛后

## 7. 红线速查（全文见 CLAUDE.md §7）

不改 vendor/；一次一个能力改动；改前备份 + 改后台账；命名测试；迁移测试；token 不进 git；experiments/pools.json 不动；不上需要外网的工具。
