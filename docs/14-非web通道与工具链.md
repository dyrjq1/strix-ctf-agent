# 14 · 非 web 通道与工具链（2026-10-30）

> 目标：在**不削弱 web / AI 安全主线**的前提下，让 agent 对 rev / pwn / misc / crypto
> 也具备能动手的最低能力。前提是合规：沙箱**运行时无外网**，工具必须预先装进
> 本机（agent 与本机同一台 VM），不在评测时下载任何东西。

## 1. 先查资料，再动手（用户规则：每 3 次改码 1 次查资料）

| # | 来源 | 关键结论 | 对我们的裁决 |
|---|---|---|---|
| N1 | Cybench, arXiv:2408.08926 | 任务就是在环境里执行命令并观察输出；拆出 subtask 后得分显著上升 | 非 web 的瓶颈不是缺万能工具，而是缺少可观察的中间步骤 |
| N2 | NYU CTF Bench, arXiv:2406.05590 | 25 个工具 + 函数调用；失败集中在多步组合而非单步命令 | 工具面要小而稳，别为每个方向堆专用工具 |
| N3 | CRAKEN, arXiv:2505.17107 | CTF writeup 知识库 + 迭代检索，NYU Bench 22%（+3pp） | 知识库收益有限，不值得在本赛投入 |
| N4 | Anthropic, Writing effective tools for agents（2025） | 工具返回要携带可判断的信号，不是原始日志 | 入口动作必须直接给出下一步 |

结论：非 web 只做一个入口原语 + 本地解题循环，不铺开十个工具。
本赛 115 题全 web；非 web 的现实目标是平台另外 9 道动手题（SAMPLE-*）。

## 2. 本次装了什么（VM，2026-10-30 15:40 UTC）

	gdb 17.1 / radare2 6.0.7 / binwalk / exiftool / strace / ltrace / jq
	python3-z3 4.13.3 / python3-pwntools / python3-capstone / python3-pil / ruby

验证：`python3 -c "import z3,pwn,capstone,PIL"` 通过；`which gdb r2 binwalk exiftool` 全在。
磁盘：12G 已用 6.8G，剩 3.9G；内存 3G。

**没装**：`qemu-user-static`（Ubuntu 26.04 源里无此包）。

回退：`sudo apt remove gdb radare2 binwalk libimage-exiftool-perl strace ltrace jq python3-z3 python3-pwntools python3-capstone python3-pil ruby`。

## 3. 代码侧本轮没动

只装工具、不改 agent 行为——先保证 web 主线测量（g3）不被污染。
入口设计见第 4 节，计划落在 `src/ctf_strix/file_triage.py`，并注册进 factory 与
`enum_guard._PROBE_TOOLS`（**新工具不被守卫认识 = 守卫失效**，这是踩过的坑）。

## 4. 设计草案（待实现）

- `file_triage(path)`：一次调用返回 `file` 类型、大小、熵、`binwalk` 命中、
  `strings` 前 N 条、是否 ELF/PE/PNG/ZIP/pyc，并**直接给下一条命令**
  （ELF → `checksec`/`r2 -A`；pyc → 反编译；zip → `binwalk -e`；png → `zsteg`）。
- 只做一次，不递归；同文件重复调用由 enum_guard 拦住。
- 题面有附件时 `_local_attachments` 已把文件注入 workspace。

## 5. 测量计划

用 `scripts/eval_sample.py` 跑 9 道动手 SAMPLE 题，turns 25；
先测 005——唯一带附件、且被启动 35 次的题。
