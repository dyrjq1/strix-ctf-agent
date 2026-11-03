# strix-ctf-agent —— Claude 统筹交接简报

> 更新：2026-11-03 · 维护者：Codex · 读者：Claude（统筹/派单/审查）
> 本文件是**唯一权威简报**。数字与结论都取自仓库实测，不凭印象。
> 与代码冲突时以代码和 `docs/11-实验台账.md` 为准；与平台冲突时以平台 API 返回为准。

---

## 1. 一句话

改造自 strix 1.7.0 的自主 CTF 解题 agent，参加清华 CTFY 智能体赛道。
`vendor/src/strix` **一行不改**，所有增强都在 `src/ctf_strix/`，运行时挂载注入。

**你的角色**：统筹者。你派任务、定验收标准、审查结果、决定取舍；执行由 Codex 做。
你不直接改代码（除非用户明确要求），也不代替用户做赛制/预算决策。

---

## 2. 当前状态（2026-11-03）

| 项 | 值 |
|---|---|
| 项目根 | `C:\Users\rjq\Downloads\strix-ctf-agent` |
| Python | `.venv\Scripts\python.exe`（系统 python 缺 `agents` 模块，**必须**用 venv） |
| 全量测试 | **480 passed**（P18 后 454；I 接线修复 +7；H P19a +19；J 落地后预计再加） |
| Git | HEAD `2078a78`，工作区积压 P16–P19a 未提交改动；**分层 commit 已获批准**，J 验收后执行（代码/文档两个提交） |
| 留出集 | `experiments/pools.json` SHA256 `55da418b…678` **未变**（本轮没跑题） |
| 台账 | `docs/11-实验台账.md`，最新条目 §4.55 = P19a（§4.54 = harness 接入修复） |
| 备份 | `backup/p19a-20261103/`、`backup/pi-20261103/`、`backup/p18-20261102/`、`backup/p17-20261102/` |
| 平台成绩 | CTFARENA 已测 48 题解出 40（83.3%），全库 40/115（34.8%） |

### 本轮（P18 → P19a）进度
- ✅ 第 1 项 流量记忆：`traffic.py`（`traffic_list` / `traffic_view`），已注册、已测试。
- ✅ 第 2 项 假设类别计数：`enum_guard` CAPEC-1000 九类机制分类 + 汇总行可观测。
- ✅ 第 3 项 CVE 路由（P19a）：离线 web CVE 索引（KEV+CPE 区间，79 产品族 / 10,678 条）+ `web_cve_lookup` 工具，台账 §4.55，**迁移验证待规则后验证批**。
- ✅ 第 4 项 triage 决策表内联（P18-4）。
- ✅ 额外：harness 接入错杀修复（I，台账 §4.54）——052 端到端已解；镜像工具面审计（L，`docs/30`）；strix 差距盘点（G，`docs/29`）。
- ⏳ J：read_file 幽灵契约修复（在跑）。

---

## 3. 比赛规则（硬约束，逐条有出处）

来源：平台 API 字段、`docs/08-CTFY-0001协议原文.md`、`docs/12-规则核对.md`、官方 QA 表。

### 3.1 练习赛 CTFARENA（当前测试场）
| 字段 | 值 | 含义 |
|---|---|---|
| suite id | `4394a10aa5d24f97a1ec3301ca718a45` | 练习套件 |
| 题量 | 115（7 easy / 48 medium / 60 hard） | **全部 web**，零附件 |
| `agents_allowed` | true | 允许 agent 参赛 |
| `agent_internet` | **deny** | agent 进程无外网，下载/查资料/调第三方 API 全部失败 |
| `internet_policy` | allow | 人类选手可以上网（我们不行） |
| `max_instances_per_team_effective` | **1** | 同一时刻只能 1 个实例 → **必须串行轮转** |
| `format` | questions | 按答案字符串判分 |
| `eval_standard` | false | 练习赛不走平台标准评测 |
| `session_end_mode` | delete，grace 900s | 会话结束即删实例，宽限 15 分钟 |
| `tcp_access` | tls_sni | TCP 题走 TLS SNI 接入 |

⚠️ **`hosted_eval` 这个字段在 API 里不存在**。可核对的是 `eval_standard=false`。
它只说明练习赛不托管评测，**不能外推到正式赛**。正式赛要交可独立运行的 agent 镜像。

### 3.2 正式赛（TPCTF 2026 · Agent Track）
| 项 | 值 |
|---|---|
| suite id | `c0d8b4e3dd3b42c095d63d7dfa66431f` |
| 时间 | 2026-11-15T02:00Z → 11-22T12:00Z（报名 11-13 截止） |
| 题量 | `challenges_withheld=true`，赛前不下发 |
| 范围 | `challenge_scope=catalog` → **六类都可能进卷**：web / pwn / reverse / crypto / misc / AI |
| 运行 | 指定 VPS（4C/8G/100G/x64），赛前上传一次，重启后自主执行 |
| 交付 | 按 CTFY-0001：读 `task.json`，写 `result.json` |
| 并发 | 平台实例配额 1；QA#26 的「≤3」是**上限许可**，不是能力保证 |
| 计分 | QA#29 动态积分：0/1 解 = 1000 分，随解题队伍数下降；无血分；早解有优势 |

**结论**：练习赛的「全 web、7/48/60、单实例、不交镜像」**不能外推到正式赛**。
正式赛是「六类初赛 + 动态积分 + 前 30 名出题 + VPS 自主运行」。

### 3.3 已核实的几个坑
- **没有每题 40 步的平台限制**。40 只是我们自己的预算；运行时必须读 `task.json.max_turns`。
- **正式赛没有选择题**。选择题通道代码已下线，知识保留在 `docs/13`。
- **CTFARENA-035 已被人工解出**（flag `FLAG{66ca8a50…}`），**不能算 agent 成绩**。
- 平台 `/api/v1/eval/*` 对 `pf_` 细粒度 token 一律 403；只有浏览器 JWT 能调。
- 平台不吃 Cookie（`cna=` 是阿里云埋点），实测 401。

---

## 4. 账号与 LLM 配置

### 4.1 平台账号（本地文件，**不要提交、不要外传**）
- 主账号 **任启骐**：user `f0aef9e3-3b15-4648-8b7c-e1e3c1a01f79`，team `e8d2cb0d-5721-42b5-969c-59f7fe368d35`
  token `<PF_TOKEN_REDACTED>`
- 合作队 **yzqcyl**（非本队副号）：user `d0ef391d-93a6-429c-94ff-09715d500092`
  token `<PF_TOKEN_REDACTED>`
  ⚠️ 是合作方另一支队伍。用它的 token 跑题 = 借合作队实例配额、成绩落对方队，**仅限诊断、须用户点头**。该队有 1 个 `CTFARENA-015` 实例在跑，**不要停它**（可能是队友的 harness）
- 已失效：`pf_sM9y…`、`pf_iMtTuxg…`、`pf_vWk1r93…`（403 revoked）；主账号新 token（`pf_p2X4…`，存用户本地）实测可用
- 长期 `POST /instances` 403 ≠ token 吊销，是探针漏带 competition_id（competition_required）；判死前先核对响应体
- 测完建议轮换

### 4.2 LLM
- 当前供应方：`https://llmapi.paratera.com`，模型 `deepseekv4.1falsh-1017`
- 曾对比：`GLM-5.3-EV`（见 `docs/17-模型对比…`）
- 关键环境变量：
  ```
  LLM_API_KEY / LLM_API_BASE / STRIX_LLM=openai/<model>
  LITELLM_LOCAL_MODEL_COST_MAP=True   # 否则 litellm 联网取价目表会超时
  STRIX_TELEMETRY=false
  STRIX_RUNTIME_BACKEND=local
  ```

### 4.3 运行环境
- 本地 Windows 只能写代码 + 跑单测；**真跑题必须在 VM**
- `ssh rjq@192.168.38.130`，密码 `54qhdxrjq`（sudo 同密码）
- VM 内项目：`/home/rjq/work/strix-ctf-agent`（非 git 仓库，用 sftp 传文件）
- 依赖安装必须 `pip install --no-deps -r requirements.lock`

---

## 5. Agent 工具清单（以 `catalogue.py` 为唯一真值）

工具按 `kind` 注册，`kind` 由 `agent._challenge_kind()` 判定。

### 5.1 所有 kind 共有（vendor base，经 `tool_trim` 保留）
| 工具 | 作用 |
|---|---|
| `exec_command` | shell。写脚本、payload 循环、拿到执行后的所有读文件 |
| `load_skill` | 加载一个方向索引（13 个），再 `read_file` 子文件 |
| `think` | 纯推理草稿，不接触目标 |

> 被裁掉的 17 个：coverage / notes / threat_model / reports 等记账类（占调用预算 27.6%、对拿 flag 零贡献），
> 以及 6 个依赖 Caido 的代理工具（镜像里没有 `caido-cli`）。
> `web_search` / `web_get_contents` 不删，换成同名桩：立即返回「无外网」，避免模型反复重试。

### 5.2 `kind=web`（web / checker / engagement）
| 工具 | 作用 |
|---|---|
| `web_cve_lookup` | 离线 CVE 查询（P19a）：KEV 标记置顶 + CPE 版本区间求值 + 别名归一（如 nginx→f5:nginx）；无版本时只给 KEV 候选并标注。数据 79 产品族 / 10,678 条，随镜像分发 |
| `http_probe` | 一次结构化 HTTP：状态、头、体、耗时；失败给 phase（DNS/TLS/CONNECT/超时） |
| `route_map` | 爬一遍站点，列 API 路径 + 从页面词汇推的 `?` 候选 |
| `method_sweep` | 一次调用把同一路径的多种 method 打完，找哪个路由有响应 |
| `path_variants` | 同一路径的大小写/编码/前缀变体，打「按字符串匹配而非按路由」的鉴权 |
| `traffic_list` | **新**：读回本轮所有 HTTP 交换 + 目标给过但从没请求过的 id |
| `traffic_view` | **新**：按 offset 分页重读某条交换，不重发请求 |
| `ai_fingerprint` | （按需）AI 组件指纹：框架、模型族、暴露的工具面 |
| `ai_cve_lookup` | （按需）组件+版本查内置规则库（2581 条），无外网时唯一 CVE 来源 |
| `ai_quick_scan` | （按需）指纹 + 匹配 CVE 一次出 |

### 5.3 `kind=file`（附件题：rev/pwn/misc/crypto）
| 工具 | 作用 |
|---|---|
| `file_triage` | 识别文件/目录：家族、大小、熵、flag 样字符串、下一条命令 |
| `decode_blob` | 多层编码解码（base64/hex/url/rot），报出成功的链 |
| `unpack_archive` | 安全解包 + 递归进嵌套包；拒绝越出输出目录的条目 |
| `hexpeek` | 十六进制 + ASCII + 偏移 |
| `elfpeek` | ELF 静态分析：info/sections/symbols/strings/gadgets/disasm |
| `elffind` | 符号/字节串 → 文件偏移 + vaddr（ret2* 需要） |

### 5.4 `kind=tcp`（远程二进制服务）
在 file 组之外另加：
| 工具 | 作用 |
|---|---|
| `tcp` | 连一次、可发 payload、回显 banner 与应答（文本+hex） |
| `tcp_batch` | 一次发多个 payload，每响应一行，用于爆破/格式化串探测 |

### 5.5 技能包（13 个方向）
`ctf-triage` `ctf-web` `ctf-pwn` `ctf-reverse` `ctf-crypto` `ctf-forensics`
`ctf-malware` `ctf-misc` `ctf-osint` `ctf-agentic-ai` `ctf-ai-infra` `ctf-ai-ml` `ctf-supply-chain`
- 只注册索引，不注册整包（整包 145 条进 system prompt 是零信息量）
- `ctf-similar-search` 被排除（依赖 Tavily API，无外网）

---

## 6. 架构地图（改哪里）

| 文件 | 职责 |
|---|---|
| `agent.py` | 官方入口：读 task.json → 判 kind → 装工具 → 跑 → 写 result.json |
| `capabilities.py` | 共享安装器，两个入口（官方 + 评测 harness）都走它 |
| `catalogue.py` | **工具单一真值表**：注册和 prompt 的 Tools 段都从这里读 |
| `prompt.py` | CTF 专用 system prompt（替换 vendor 的 103k 字符通用提示） |
| `tool_trim.py` | 运行时裁 `_BASE_TOOLS`，不碰 vendor 源码 |
| `http_probe.py` / `discovery.py` / `variants.py` | web 四原语 |
| `traffic.py` | 流量台账 + 两个只读原语（P18 新增） |
| `file_triage.py` / `nonweb.py` | 附件题与 TCP 原语 |
| `aisec/` | AI 安全：指纹、CVE 规则库、SSRF 闸门；`aisec/web_cve.py` + `data/web_cve_*.json` = 通用 web CVE 索引（P19a，`scripts/build_web_cve.py` 离线构建，确定性 sha256） |
| `enum_guard.py` | 枚举守卫：重复响应计数 + CAPEC 机制类别计数（P18）+ bundle 重读守卫 |
| `journey_guard.py` / `finish_guard.py` / `sweep_guard.py` / `deadline_guard.py` | 其余运行时守卫 |
| `guard_mount.py` | 把守卫挂到 strix 的三条调用路径上（常规工具 / Shell / 子 agent） |
| `evidence.py` | 证据链：观测 → 是否支持假设 |
| `skillpack.py` | 技能索引注册与路由提示 |
| `autosubmit.py` / `platform_env.py` | run 内提交（实例结束后即销毁，事后补交必失败） |
| `tcp_bridge.py` / `vpn.py` / `jail.py` | 接入统一、隔离 |
| `usage_meter.py` / `flag_extract.py` | token 计量、flag 抽取 |

**红线**：不改 `vendor/`；扩展一律走 `strix.agents.factory.register_agent_tools`。

---

## 7. 工作原则（Codex 执行，Claude 审查时按此判断）

### 7.1 八步流程（用户定的）
1. 定方向需求（如「提高 misc 能力」）
2. 查成功案例（往届/同类比赛、开源 agent、论文）
3. 分析对方代码，与自身对比：漏洞发现效率、工具强度、组织方式
4. 给改进方案，**先检查是否符合比赛规则**
5. 改代码，或复用 GitHub 上可直接用的工具/模板
6. 测试，验证是否**真实增强**能力（不是「在这批题上变好」）
7. 出报告
8. （可选）分发一部分给 CodeBuddy 提效

### 7.2 查资料的比例
**每改 3 次代码，至少查 1 次资料**，优先权威来源：CTF 官方/知名赛事 writeup、
MITRE CAPEC / ATT&CK、OWASP WSTG、arXiv 论文、SANS。
规则类问题（能不能联网、能开几个实例、有没有选择题）**必须先查权威出处**，不许凭印象。

### 7.3 防过拟合四条红线
1. 不许对着失败日志改 prompt 里的具体字符串（看到卡在 `/admin.php` 就写「试试 /admin.php」）
2. 不许用留出集调参。跑过一次、看了结果、再改代码 → 这批题作废，必须重抽
3. 不许把「这批题全绿」当验收通过
4. 不许拿榜单名次当优化目标

### 7.4 三个判据
- **命名测试**：改动的一句话描述里不许出现题号、IP、具体路径、具体 flag。写不出来 → 标 S 级并写触发条件
- **迁移测试**：开发题提升 X%、留出集提升 Y%。`Y < 5 个百分点` 判过拟合
- **消融**：撤掉改动再跑同题。变差→有效；没变化→噪声，删掉；变好→回滚

### 7.5 两条纪律
- **预算（时间/轮次/并发/token）不得单独调**，必须依附能力改动并写物理依据
- **一次只改一处**。例外：接线类修复（工具没注册、变量名写错、路径拼接错）可合并

### 7.6 工程纪律
- 改前备份到 `backup/<slug>-<日期>/`，改后在 `docs/11-实验台账.md` 追加一节并写回滚路径
- 不主动 git commit / 不建分支
- 写文件一律「临时文件 + `os.replace` + 锚点唯一性 assert」；`pathlib.write_text(newline='\n')` 在 Windows 会先截断再抛错（踩过一次，写坏了 `nonweb.py`）
- 保持原文件行尾（agent.py/catalogue.py/http_probe.py/file_triage.py 是 CRLF；nonweb.py/traffic.py/enum_guard.py/capabilities.py 是 LF）

### 7.7 本项目实测结论（别重复踩）
- 上下文「按龄裁剪」是**负优化**：缓存命中 95.7% → 57.8%，等效成本涨 6 倍，已回滚为内容封顶
- 失败题 p50 267–551s，成功题 p50 60–70s → **瓶颈是方向选择，不是预算**
- 练习榜 14 支 agent 队全是 0 分 0 尝试 → rank 13 不代表落后

---

## 8. 测试与跑题

### 8.1 单测（本地）
```powershell
cd C:\Users\rjq\Downloads\strix-ctf-agent
set TMP=%CD\ctfwork\pt_x
set TEMP=%TMP%
.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider --basetemp=%TMP%\base
```
基线 **447 passed**。低于此数就是回归。--basetemp 不能省：本机 pytest 仍会去 LOCALAPPDATA 建 pytest-of-rjq 并报 WinError 5。

### 8.2 跑题（VM 内，串行）
```bash
cd /home/rjq/work/strix-ctf-agent
export PF_TOKEN='...'
export LLM_API_KEY='...' LLM_API_BASE='https://llmapi.paratera.com/v1'
export STRIX_LLM='openai/deepseekv4.1falsh-1017' STRIX_RUNTIME_BACKEND=local
export LITELLM_LOCAL_MODEL_COST_MAP=True
export PYTHONPATH=$PWD/src:$PWD/vendor/src
echo '[{"id":"CTFARENA-009","difficulty":"medium"}]' > ~/plan.json
nohup .venv/bin/python scripts/batch_eval.py --plan ~/plan.json --turns 25 --wallclock 600 \
  --out ~/results.jsonl --token "$PF_TOKEN" > ~/run.log 2>&1 &
tail -20 ~/run.log; cat ~/results.jsonl
```
- `batch_eval.py` 自己起实例、跑 agent、提交，每题 append 到 jsonl
- 难度自动放大预算：easy=(turns, wall)，medium=(1.6x, 1.5x)，hard=(2.4x, 2.3x)
- 实例 TTL 10800s；删实例后重起有 30–60s 开销
- **实例与会话结束即销毁**：提交必须在 run 内完成

---

## 9. 历史数据（判断「是否真的变强」的基线）

| 指标 | 值 |
|---|---|
| CTFARENA 已测 | 48 / 115 |
| 解出 | 40（83.3% of tested，34.8% of all）；052 系 harness 接入错杀，修复后 e2e 已解 |
| 本队总解出 | 50 = agent 40 + 人工 10 |
| 榜单 | rank 13 / 88，score 49；14 支 agent 队全部 0 分 |
| 成功题 p50 | 60–70s |
| 失败题 p50 | medium 267s / hard 551s（max 815s） |
| 成功题 p90 | 253s |
| 单题 token | 281k – 1.25M |

历史统计更正（2026-11-03）：VM 全量 jsonl 里有 **8 条 `skipped:true`** 曾被误记为「跑过未解出」——CTFARENA-052 ×3、CYBENCH-011 ×2、CYBENCH-001、XBOW-007、XBOW-052，error 全是 `SKIPPED(需隧道)`。这批题实际从未进 agent。

### 从未解出的题型（优先级参考）
| 组 | 题 | 信号 |
|---|---|---|
| agentic_ai | 043 / 047 | 043 跑 4 次全败（6.4–195s）；047 全库倒数第 13 |
| 认证类 | 020 / 021 | 021 全库第 6 低；020 跑 1 次 507s 全败 |
| 设计缺陷 | 017 / 018 | 018 跑 4 次全败，耗尽 40 轮 |
| 供应链 | 064 | 3 次全败，最慢 331s |
| 多网络 | 049 | SSRF+webhook+pivot+multi_flag，需主机间跳转 |

（052 已从本表移除：瓶颈是 harness 接入判据，不是 CVE 知识；接入修复后 agent 27.2s 解出。）

---

## 10. 怎么给 Codex 派任务（Claude 用这个模板）

```
【目标】一句话，可验证。
【背景】相关文件/指标/上次结论（给路径，不要复述）。
【范围】允许改哪些文件；明确不许碰 vendor/。
【验收】具体命令 + 期望结果（如 "pytest tests -q 全绿且 >= 447"）。
【红线】本次特别需要注意的（如 "不得新增预算参数"、"不得针对某题改字符串"）。
【回报】要数据：改了哪些文件、测试前后数字、消融结果、未做的部分。
```

派单原则：
- 一次一个能力改动，不要打包三个不相关的改动
- 要求「先给方案再动手」的，明确写出来
- 要求查资料的，指定来源级别（官方 writeup / 论文 / 标准文档）
- 涉及规则判断的，要求附出处链接或 API 字段名

## 11. 怎么审查（Claude 的验收清单）

1. **是否真的生效**：工具是否出现在真实注册表里（`tests/test_toolset_wiring.py`），不是只写了函数
2. **是否有反例测试**：只测「该响的时候响」不够，还要测「不该响的时候不响」
3. **是否做过消融**：撤掉改动，测试/行为是否变差
4. **是否碰了红线**：改 vendor？单独调预算？对失败日志写死字符串？
5. **命名测试**：能不能用一句不含题号/IP/路径/flag 的话描述这个改动
6. **是否可回滚**：备份存在、台账有记录、回滚路径明确
7. **数字是否可复现**：测试数量、哈希、耗时是否给出并且与基线对得上
8. **是否过度设计**：新增的抽象层是否真的被用到；能否用更少的代码达到同样效果

---

## 12. 环境坑（Windows）

- 本机 shell 会吞引号：**不要用 `python -c "..."`**，先把脚本写到 `ctfwork\*.py` 再执行
- 临时脚本放 `ctfwork\`；`%TEMP%` 根目录有 `mcp.py` 会遮蔽 `mcp` 包
- pytest 前必须把 `TMP`/`TEMP` 指向 `ctfwork\pt_x`，否则 `pytest-of-rjq` 触发 WinError 5
- `rg` 用 `-g` 过滤，不要用 `*.py` 通配（PowerShell 会自己展开）
- 控制台是 GBK：打印中文/emoji 可能 `UnicodeEncodeError`，用 `PYTHONIOENCODING=utf-8` 或写文件再读
- `pathlib.write_text(..., newline='\n')` 在 Windows 会**先截断再抛 ValueError**，务必用临时文件 + `os.replace`

---

## 13. 汇报格式

中文、结论先行、给数据、20 行以内为常态。
改了什么 / 测试前后 / 消融结果 / 没做什么 / 下一步建议。

## 14. 你的角色边界（Claude 必读）

你负责：定方向、拆任务、写验收标准、审查产出、决定采纳或回滚。
你不负责：直接改代码（除非用户明确要求）、替用户决定预算或赛制、未经授权跑真题。

三条硬边界：

1. 不许用「这批题分数变高」换取对防过拟合红线的绕过。
2. 涉及规则的问题先查平台 API 字段或官方 QA，不许凭印象。
3. 一次只批一个能力改动；接线类修复（工具没注册、变量名错、路径错）可以合并。

你看到的数字如果和 docs/11-实验台账.md 最新一节对不上，以台账为准，并要求 Codex 更正简报。

## 15. 平台查询入口（MCP）

查规则、查题目、查成绩只有这一个合法入口：

- POST https://ctfy.tsinghua.edu.cn/api/v1/mcp/
- 头：Authorization: Bearer $PF_TOKEN；Content-Type: application/json；Accept: application/json, text/event-stream
- 协议：JSON-RPC 2.0；响应是 SSE（event: message，data: {...}）
- 96 个工具；判规则时优先看 API 字段，不要只看文档描述

常用工具名：list_competition_challenges、start_instance、get_instance、stop_instance、submit_answer、verify_answer、get_my_solves、list_suites、get_competition、list_my_tasks。

token 不在仓库里：主账号和副账号的 pf_ 开头 token 在用户本地的 HANDOFF-CTFARENA-20261030.md，或在会话里向用户要。不要把 token 写进任何会被 git 跟踪的文件。

注意：这个 agent 本身在比赛里没有外网；你是统筹者，在宿主机上可以查资料、可以调 MCP，但不要把「agent 能上网」写进任何设计。


可直接复制的只读探测（列出套件）：

```bash
curl -sS https://ctfy.tsinghua.edu.cn/api/v1/mcp/ \
  -H "Authorization: Bearer $PF_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_suites","arguments":{}}}'
```

响应是 SSE：JSON 在 data: 那一行里，不是整个响应体。不要把 token 打印到日志。

## 16. 当前待办与不做清单

待办（P19a 后，按顺序）：

1. J：read_file 幽灵契约修复（在跑）——提示/技能索引里指向未注册工具的指引改写为 exec_command/view_image。
2. K：反证/闭合 + 换机制提示块（600–1,500 字符）。外部依据：arXiv 2605.21497，识别层是首要瓶颈、编排不抬天花板。
3. 分层 commit（已批准）：J 验收后执行，代码/文档两提交。
4. 规则 11-07 后的验证批：P18+P19a+J+K 一起在未参与改动的题上测迁移（含 4 道未测 agentic_ai）；experiments/pools.json 不能动。
5. 镜像 A 档工具（L 审计 `docs/30`）：pycryptodome/z3/Pillow 优先，pwntools 传递依赖必须完整闭包进 lock；装完 `_NEXT` 白名单与断言同步。
6. 历史 skip 4 题（CYBENCH-011/001、XBOW-007/052）用修好的接入判据重跑归因。

已判定不做：

- 不单独调预算（CTF_ATTEMPTS、turns、wallclock），必须依附能力改动
- 不加选择题通道（正式赛没有选择题）
- 不包装 gdb（exec_command 已能跑 gdb -batch）
- 不改 vendor/，不 fork strix
- 不引入需要外网的工具或 API（agent 运行时无外网）
- 暂不做多 agent 并发：平台实例配额 1，先保证单实例串行轮转稳定

## 17. 已知盲区（别当成已覆盖）

- 40 个解几乎全来自 web；pwn / crypto / misc 的真实解出率没有单独统计
- ELF 工具只在手工构造的样例上验证过，没有真实 ELF 端到端
- Docker 镜像本机无法构建（无 docker/WSL），只能靠 CI；gdb/strace/ltrace/capstone 分层 commit 前只在未提交工作树
- verify-answer 没有用真实例打过一次
- P16 / P17 / P18 / P19a 四批改动都没在真题上验证过（唯一例外：052 作为 I 接入修复的单题 e2e 走通了官方链路）
- 镜像里没有浏览器二进制（playwright 只有 Python 包）、没有 `Crypto` 命名空间（cryptography 不等价）——工具面缺口全表见 `docs/30`
- 正式赛规则 11-07 才出；在此之前不要按练习赛规则外推

## 18. 你在本机有什么（别去用不存在的东西）

- Claude Code 在 C:/Users/rjq/Downloads/strix-ctf-agent 下启动；这个目录就是项目根，不需要再找。
- 你的 MCP 配置是空的（mcpServers 为空），所以：你能读文件、能跑 shell、能搜网，但没有直接挂在平台上的 MCP 工具。
- 要查平台，用 shell 自己发 JSON-RPC 到 MCP 端点；token 每次从用户或本地 HANDOFF 文件取，不要写进仓库。
- 你**没有** WorkBuddy 桥（那是我这边的工具），不要假设自己能调它。
- 你能读整个仓库，但 reference/ 和 traces/ 含真实 flag，不要复制到任何会被提交的地方。

## 19. 启动时先读什么

1. 本文件第 1、2、3 节：现在在哪、规则是什么
2. docs/11 最后一节：最近一次真实改动和它没验证的部分
3. docs/23：哪些题型从来没解出过
4. docs/25：评测改动的红线

不要一上来就读 vendor/ 或 src/ 全量代码；先读这四份，再按任务定点读实现。

## 20. 你要怎么和我协作

固定回路：

1. 你出任务单（第 10 节的六项格式），一次一件事。
2. 我回方案 + 影响面 + 验收命令；涉及规则的我附字段或出处。
3. 你确认方案符合规则和红线，再批准动手。
4. 我改完给数据：文件清单、447 passed、消融、未做部分。
5. 你按第 11 节八条验收；不达标退回，不要打折。
6. 通过后我写进 docs/11 台账并留回滚路径。

你可以否决我，但必须给依据；我也可以指出你的任务单缺项。
