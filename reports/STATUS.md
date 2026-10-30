# strix 现状速览

> 更新时间：2026-10-29 13:30 · 基线 vendor strix 1.7.0 · 改造代码 `src/ctf_strix/` 约 7300 行 · 回归测试 63 条全绿

## 一句话

vendor 里的 strix **一行没改**，所有改造都在 `src/ctf_strix/` 里通过运行时挂载注入，
升级 strix 不需要 rebase。SAMPLE 套题 14 题里 11 道可测题**全部通过**，
剩下 3 道是平台未完成题（README 是占位符、服务是 health-check stub）。

## 评测结果

| 项 | 值 |
|---|---|
| 套题 | SAMPLE `e4e78ff3...`（14 题） |
| 可测题 | 11 题 |
| 通过 | **11 / 11** |
| 不可测 | 003 / 004 / 012 —— 平台未完成题 |
| 单题耗时 | 125–618s |
| 单题 token | 281k–1.25M |

昨日判 FAIL 的 8 题今日全部翻盘，根因是**判定链缺陷**（三层叠加），不是模型能力问题。

## 改造覆盖的六层

### 1. 接入归一化
`tcp_bridge.py` / `vpn.py`

平台题的接入有三种：`tls_sni`、`public_port`、`vpn`。把这件事丢给 agent 是错的——
它要花 3-5 个 turn 试 `openssl s_client -servername`、`--noproxy`，这些 turn 对
"能不能解出题"零信息量。现在统一起本地 TCP 桥，agent 永远只看到 `127.0.0.1:PORT`
的明文服务；`.internal` 域名走 WireGuard 隧道（004 从 600s 零进展变成 217s 通过）。

### 2. 隔离
`jail.py`

`unshare -m --propagation private` + tmpfs 盖掉 `/workspace`、`/tmp`、`/root`，
只 bind 本题的 box。

> 为什么必须有：之前 agent 可以 `cd /workspace` 读评测脚本、从 `ps` 抄 token 打平台
> API，004 单题烧掉 200 万 token。没有边界的 agent 会把评测变成给自己放水。

### 3. 工具面裁剪
`tool_trim.py`

默认 44 个工具裁到 27 个。砍掉 17 个记账类（coverage / notes / threat_model /
reports，占调用预算 27.6% 且对拿 flag 零贡献）+ 6 个依赖 Caido 的代理工具
（本机不存在，调用必失败）。做法是运行时替换模块级 `_BASE_TOOLS`，不动 vendor 源码。

### 4. 运行时守卫
`enum_guard.py` / `journey_guard.py` / `finish_guard.py` / `guard_mount.py`

一条贯穿所有守卫的教训：**写在 prompt 里的自我约束会随轮次衰减**。

- 枚举规则写了两版都没生效——模型在第 5 次调用时，前 4 次探测已经被后来的工具
  输出埋掉了，它对"我重复了"没有感知。程序里的计数器不会忘。
- 同理有"先走完正常用户旅程""finish_scan 前三问"——都是 prompt 版失败、硬约束版生效。

`guard_mount` 存在的理由：strix 造 agent 走**三条不同的路**（常规工具列表 /
Shell capability / 子 agent），只挂一条会漏，必须全部接上。

### 5. 组合时限
`deadline_guard.py`

| 闸门 | easy | medium | hard | 作用 |
|---|---|---|---|---|
| `wall` 硬上限 | 480s | 780s | 1200s | 绝对兜底，到点杀 |
| `soft` 软截止 | 300s | 480s | 740s | 不杀，注入"必须收敛" |
| `stall` 停滞 | 85s | 95s | 110s | 无外部活动即判死 |
| `grace` 宽限 | 20s | 20s | 20s | 已见答案则给收尾机会 |
| `turns` | 28 | 42 | 60 | 成本直接约束 |

设计论点：墙钟同时承担了"该收工了"和"立刻杀掉"两件冲突的事。失败原因不同处置就
不同——**方向错了**该打断并逼它换机制（软截止），**真卡死了**给再多时间也没用
（停滞检测立刻杀）。

### 6. 判定与账本
`eval_sample.py` / `autosubmit.py` / `flag_extract.py` / `usage_meter.py`

- **提交必须在 run 内完成**：实例在 run 结束后即被销毁，父进程事后补交必撞
  `instance_not_found`。改为子进程写 sidecar → 父进程回读，sidecar 为唯一权威来源。
- **答案判据用队伍账本** `my_team_solved_question_ids`，不用实例级
  `answered_correctly`——后者在同一实例重跑时仍是 true，会把可测题误判成不可测。
- **token 计数自己持有**：被 SIGKILL 的进程没有机会保存任何东西。
- **占位题自动识别**：命中 `TODO: replace this README with the artifact` 直接记
  `platform_invalid`，不跑 agent（012 因此省下 420s + 916k token）。
- **答案抽取防跨题污染**：工作目录跨 run 复用，上一题留下的笔记会把别的题的 flag
  带进上下文。

### 7. AI 安全能力（按提供的 6 个文件）
`aisec/`（5 模块，1840 行）

- `aig_probe.py`：AI 组件指纹（gradio / dify / comfyui）+ SSRF 闸门（白名单优先、
  禁重定向、线程超时防 ReDoS）+ 规则库 CVE 情报
- `verrule.py`：版本比较，处理 `1.53.1rc1` 这类数字+字母混合段、`1.0` vs `1.0.post1`
- `tools.py`：三个异步工具，先过闸门再查规则库
- `mock_multi.py`：多服务 mock 靶场（端口 0 由内核分配）
- `build_kb.py`：YAML → JSON 确定性转换

### 8. CTF 技能包 + 规则库（v1.0 交付包接入）
`skills_strix/` + `aisec/data/` + `skillpack.py`

- **12 个方向索引技能**（triage / web / pwn / crypto / reverse / forensics / misc /
  ai-infra / ai-ml / osint / malware / similar-search），走 strix 原生 `load_skill`
- **只注册索引**，不注册整包：整包是 145 条进每个 agent 的 system prompt（≈8.5k 字符），
  其余 133 个是没有 frontmatter 的参考子文件，对模型零信息量
- 索引装载时插入绝对路径提示，指向 jail 内的 bind 挂载点，子文件走 `read_file`
- **规则库 11 MB**：163 指纹 / 147 组件 / 2581 条 CVE，与引擎 schema 直接对齐

接入细节与偏差记录见 `reports/skillpack-integration.md`。

## 三个已知短板

| # | 问题 | 证据 | 方向 |
|---|---|---|---|
| 1 | **soft 截止不生效** | 006 在 420s 时收 389s，480s 时收 **481.1s**，一直干到被砍 | 软截止触发后砍掉工具集，只留 `submit_answer` / `finish` |
| 2 | **checker 型题吃时限红利是假的** | 答案落在服务端状态，撞墙照样判过，多给时间只多烧 token | 对 checker 型题单独设更紧的 wall |
| 3 | **技能"可得"但不必用** | 同一道 mock 题两跑：一次加载了 ctf-ai-infra，一次完全跳过直奔工具 | 硬约束（首轮注入"你还没 triage"）或把判决表内联进 prompt |

## 供应商侧的一个真问题

`answered_correctly` 是**实例级**字段，随实例带下来。同一实例重跑时它仍然是 true，
所以**不能当作"这题还能不能测"的判据**——唯一可信的是 `challenge API` 的
`my_team_solved_question_ids`（队伍账本）。这个坑让第一天的 8 题误判成 FAIL。

## 文件地图

```
src/ctf_strix/
├── agent.py              运行时组装 strix agent
├── jail.py               tmpfs 命名空间隔离
├── tcp_bridge.py         接入归一化（本地明文桥）
├── vpn.py                WireGuard 隧道
├── tool_trim.py          工具面裁剪
├── enum_guard.py         枚举收敛守卫（硬约束）
├── journey_guard.py      用户旅程守卫（硬约束）
├── finish_guard.py       收工守卫（无 flag 不许结束）
├── guard_mount.py        守卫挂载点（三条路径全覆盖）
├── deadline_guard.py     组合时限四闸门
├── autosubmit.py         run 内提交 + sidecar
├── flag_extract.py       可信 flag 抽取
├── usage_meter.py        token 计量
├── guard_mount.py        守卫挂载
├── local_backend.py      strix 本地后端适配
├── skillpack.py          CTF 技能包接入（只暴露索引 + 路径提示）
├── skills_strix/         12 分类 / 190 md 技能包
└── aisec/                AI 安全能力 + data/（11 MB 规则库）

scripts/
├── eval_sample.py        评测主控（1701 行）
└── run_strix_ctf.py      一题一进程入口

tests/
├── test_autosubmit.py    10 条
├── test_aisec.py         27 条
├── test_aisec_data.py     4 条   规则库条数与已知 CVE 数
└── test_skillpack.py     22 条   索引集合 / frontmatter 位置 / 266 条链接
```

## 相关文档

| 文档 | 内容 |
|---|---|
| `docs/01-strix-改造点地图.md` | 改造点全景 |
| `docs/02-基线实验报告.md` | 改造前的基线数据 |
| `docs/04-改进实施记录.md` | 逐项实施记录 |
| `docs/05-运行时守卫与契约校验.md` | 守卫设计细节 |
| `reports/sample-eval-final.md` | 12 题全量评测报告 |
| `reports/ctfy-feedback.md` | 对 CTFY 平台的反馈 |
| `reports/HANDOFF.md` | 交接说明 |
| `reports/skillpack-integration.md` | 技能包 / 规则库接入记录与偏差 |
