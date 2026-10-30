# 交接给 Codex：strix-ctf-agent

> 写于 2026-10-29 · 作者：上一棒 agent · 读者：接手编码的 AI 助手（Codex）
> 这份文档的目的：让你在**不看我俩之前几十轮对话**的前提下，能独立判断该做什么、不该做什么。

---

## 0. 三十秒版本

我们在改造一个开源 CTF agent（[strix](https://github.com/usestrix/strix) 1.7.0），
让它能参加清华 CTFY 平台的智能体赛道。改造方式是**外层包裹**：上游 `vendor/src/strix/`
一行不改，所有增强放在 `src/ctf_strix/`，运行时挂载注入。

现在已经能跑、已经打成容器镜像、已经推到平台仓库。
**功能缺口已补：GAUNTLET 的渗透报告投递已实现（`src/ctf_strix/engagement.py`）。
现在挡住正式测评的是「重建并推送 v2 镜像 + 真机验证报告字段名」，不是代码。**

---

## 1. 背景：平台契约是什么

平台文档代号 **CTFY-0001**，**全文已放在 `docs/08-CTFY-0001协议原文.md`**（44KB，从前端 bundle 里提取的完整版，
比网页渲染更全）。关键条款我在下面列了一遍，日常够用；碰到细节去查原文。

### 1.1 容器怎么和平台交互

平台跑你的镜像时，工作目录由 `CTFY_WORK_DIR` 指定（通常 `/ctfy/work`），里面有：

| 文件/变量 | 内容 |
|---|---|
| `task.json` | 本次任务的完整简报（题型、目标、预算） |
| `$CTFY_TOKEN` | bearer token，调平台 API 用 |
| `$CTFY_PLATFORM_URL` | API 根地址 |
| `$CTFY_EVAL_CHALLENGE_ID` / `$CTFY_EVAL_COMPETITION_ID` | 题目与比赛 id |
| `$CTFY_EVAL_MAX_TURNS` | 软轮次预算，**不存在表示无上限**（不是 0） |
| `$CTFY_EVAL_DRY_RUN` | 值为 `1` 时表示这是镜像合规检查，不是真题 |
| `$LLM_FLAVOR` / `$LLM_API_KEY` / `$LLM_MODEL` / `$LLM_BASE_URL` | 模型凭据 |

### 1.2 你交什么回去

往 `$CTFY_WORK_DIR/result.json` 写 JSON（路径以 `task.json` 的 `result.path` 为准，可能是别的名字）：

```jsonc
{
  "schema_version": 2,
  "answers": { "flag": "ctfy{...}" },   // key 是 question id，不是固定字符串
  "turns": 17,
  "input_tokens": 120000,
  "output_tokens": 8000,
  "stop_reason": "done",
  "writeup": "markdown，给人看的"
}
```

### 1.3 三条最容易踩的硬规则

1. **`stdout` 不被读取。** 用户自带镜像没有 stdout fallback。所以日志随便打（我们现在就在打），
   但**结果必须在文件里**。这一点 `docker/entrypoint.sh` 已经用三道保险兜住了。
2. **`solved` 字段不算数。** 平台按自己记录的提交判断，镜像自称没用。
   判分口径是队伍账本 `my_team_solved_question_ids`，**不是**实例级 `answered_correctly`
   （后者在题目被重新拉起后会归零，用它判分会把做对的题判成 FAIL，我们犯过）。
3. **实例在 run 结束就销毁。** 提交必须发生在 run 内部。父进程事后补交一定撞
   `instance_not_found`。这就是 `autosubmit.py` 那个 sidecar 存在的原因。

---

## 2. 两种题型，差别决定一切

| | `instance` 模式 | `engagement` 模式（GAUNTLET） |
|---|---|---|
| 目标 | 一台靶机 | 一整套企业内网（多主机 + 网段） |
| `scope` | 靶机 URL 或附件 | 主机名 + CIDR，例如 `["edge.meridian.test", "10.20.0.0/16"]` |
| `questions` | 有，要逐个答 | **空的，这是刻意的**——平台不告诉你它在找什么 |
| 交付物 | `POST /api/v1/submissions` 交 flag，或写进 `answers` | `PUT /api/v1/competitions/{competition_id}/challenges/{challenge_id}/report` 交报告 |
| 起靶机 | `target_instance` 为 `null` 时**要自己** `POST /api/v1/instances` | `target_instance` 非空，**已经在跑了，绝对不要起实例** |

### engagement 模式的四条要点（这是你要实现的部分）

1. **`target_instance` 非空 = 靶场已就绪，容器已在该网络内。** 再调 `POST /api/v1/instances`
   会起第二个靶场、烧掉配额，而且你测的是一个连不上的环境——表现成一堆连接错误，
   看起来像模型放弃了。
2. **报告可反复覆盖。** `PUT` 是替换语义，最后一次保存的版本参与评分。
   所以策略应该是**边做边存、越早越好**，而不是最后攒一份大的。
   一个跑完但没存报告的 run，等于什么都没交付。
3. **平台在每次保存时从正文里抽证据评分。** 具体描述的发现立刻计分，
   含糊的描述不计。所以报告里写「在 `/api/doc/:id` 发现 IDOR，用 user A 的 token 读到了 user B 的文档 42」
   远比「发现了访问控制问题」有效。
4. **报告要写成渗透测试交付物**：做了什么、怎么做的、看到了什么、影响是什么。
   只要结论不要过程是错的。

---

## 3. 现在的代码长什么样

```
src/ctf_strix/
├── agent.py            入口：读 task.json → 跑 strix → 写 result.json
├── platform_env.py     LLM_* → STRIX_LLM / LLM_API_BASE 桥接（只填空缺不覆盖）
├── jail.py             unshare -m + tmpfs 沙箱，把 agent 关进本题盒子
├── skillpack.py        技能包：只注册 12 个分类索引（不是 190 篇，见 §7 坑 3）
├── autosubmit.py       提交 sidecar：子进程内提交、落盘、父进程回读
├── flag_extract.py     flag 抽取，按"离本题靶机远近"打分，防抄到别题
├── enum_guard.py       枚举收敛守卫
├── journey_guard.py    用户旅程守卫
├── finish_guard.py     收工守卫（没 flag 就 finish 会被拒）
├── guard_mount.py      钩子挂载 + 接线验证
├── deadline_guard.py   组合时限：wall / soft / stall / grace
├── skills_strix/       12 分类 / 190 篇技能文档（4.1 MB）
└── aisec/              AI 安全：163 指纹 / 147 组件 / 2581 条规则（11 MB）

scripts/
├── run_strix_ctf.py    单题入口（本地跑一次扫描）
└── eval_sample.py      平台批量评测主控（约 1700 行，最复杂的文件）

docker/
├── Dockerfile          python:3.12-slim + 124 个钉版本依赖 + 工具链，非 root
└── entrypoint.sh       三道保险保证 result 文件一定存在

vendor/src/strix/       上游 1.7.0，**不要改**
tests/                  118 条回归（engagement / 附件注入 / 收工守卫 / 平台协议）
docs/                   01-07，改造思路与决策记录
reports/                评测报告、平台反馈
```

### 关键调用链

```
docker entrypoint.sh
  └─ python3 /app/src/ctf_strix/agent.py
       ├─ platform_env.normalise()          桥接模型凭据
       ├─ 读 task.json，判断 dry_run / 题型
       ├─ _targets_from(task)               解析目标（engagement 会剥 CIDR 补 scheme）
       └─ _run_agent(...)
            ├─ install_backend()            本地运行时后端
            ├─ 装五个守卫（mount / enum / journey / finish）
            ├─ install_ctf_toolset()        裁剪工具面
            ├─ run_strix_scan(...)          跑上游 strix
            │    └─ event_sink 逐条抓工具输出 → _extract_flag → answers[qid]
            └─ 返回 turn 数
       └─ 写 result.json（finally 块，异常也写）
```

---

## 4. engagement 报告投递（✅ 已实现，缺真机验证）

> 2026-10-30 状态：下面 4.2 的方案已经落地。`src/ctf_strix/engagement.py`
> 提供 `ReportPublisher` + `save_report` 工具 + `finish_scan` 外层钩子，
> `agent.py` 已接入并按题型切 goal。4.2 保留作设计记录；验收缺口见 4.3。

### 4.1 已实现的内容

- `engagement.py`：`PUT .../report`，请求体按 `content → markdown → body → report`
  四个候选字段尝试，只对 400/413/415/422 换字段，401/403/404/5xx 只发一次；
  正文 hash 去重 + `min_interval` 节流；网络失败永不抛异常。
- 正文脱敏：精确替换已知 token，并掩码 JWT / `Bearer xxx`；**不按长度一刀切**
  ——文档 id、MD5 是计分证据，掩掉等于删分。
- 三条保存路径：模型显式 `save_report`（跑在线程里，不阻塞事件循环）、
  每 8 条工具输出的后台自动保存、`finish_scan` 外层钩子 + run 结束后的最终保存。
- 空报告不发：一条工具输出都没有时跳过，避免覆盖平台上一版已计分的正文；
  模型写过的正文也不会被迟到的自动摘要覆盖（`authored` 后拒绝 `source="auto"`）。
- `_read_goal()` 已按题型分流，engagement 读 `config/ctf_goal_engagement.txt`，
  不再吃 `Do NOT write vulnerability reports.` 这条反向指令。
- `config/` 六个 goal 文件已补齐（原先整个目录缺失，镜像构建会崩）。

### 4.2 要做的事

**① 新增 `src/ctf_strix/engagement.py`**

建议接口（你可以按自己判断调整，但保持职责单一）：

```python
def put_report(platform_url: str, token: str, competition_id: str,
               challenge_id: str, markdown: str) -> tuple[bool, str]:
    """PUT 一份 engagement 报告，覆盖上一版。

    Args:
        platform_url: 如 https://ctfy.tsinghua.edu.cn
        token: CTFY_TOKEN
        competition_id: task.json 顶层 competition_id
        challenge_id: task.json 的 challenge.id
        markdown: 报告正文

    Returns:
        (成功与否, 说明)。失败不要抛异常——报告投递失败不能拖垮整个 run。
    """
```

端点：`PUT {platform_url}/api/v1/competitions/{competition_id}/challenges/{challenge_id}/report`

请求体字段名**需要实测确认**（可能是 `{"content": "..."}` 或 `{"body": "..."}` 或 `{"markdown": "..."}`）。
先用一个假 challenge id 打一次，看 400 的报错提示里要什么字段——这是最快的确认方式。
不要靠猜写死。

**② 改 `agent.py` 的 `_run_agent()`，加周期性投递**

engagement 模式下，每 N 个 turn（建议 8-10 轮）把当前进展合成一份报告 PUT 一次。
不要等最后——平台每次保存都抽证据计分，中途保存的发现已经拿到分了。

素材来源：现有的 `event_sink` 已经在逐条收集工具输出（`captured` 列表）。
从中提炼「做了什么 / 发现了什么 / 证据是什么」。

**③ 按题型切 goal**

`_read_goal()` 现在读 `config/ctf_goal.txt`（flag 导向）。engagement 模式要用另一份，
核心是：「这是一个渗透测试委托。目标不是找一个 flag，是产出一份有证据的测试报告。
每 8 轮保存一次进展到报告接口。」

**④ 补测试**

`tests/` 下新增 `test_engagement.py`，至少覆盖：
- 报告 PUT 的 URL 拼接正确（含 competition_id / challenge_id）
- 网络失败时返回 False 而不抛异常
- engagement 模式下 goal 用的是报告导向版本，instance 模式用 flag 导向版本
- `target_instance` 非空时不会去调 `POST /api/v1/instances`

### 4.3 验收标准

- [x] `pytest -q` 全绿 —— 2026-10-30：118 passed, 1 skipped
      （skip 的是没装 `agents` SDK 的 docstring schema 用例；镜像里必然有）
- [x] 报告正文里有具体路径、参数、证据，而不只是结论
      （`test_build_report_keeps_evidence_parts` 锁结构；脱敏用例锁"证据不被误删"）
- [ ] **真机**：`docker run` 跑 fake engagement task.json，日志里出现
      `PUT .../report`，且失败时 result.json 仍正常写出
- [ ] **真机**：确认平台实际接受的请求体字段名（四个候选靠 422 重试兜底，未实测）
- [ ] **真机**：确认 `save_report` 在真实 `agents` 运行时下注册成功
      （日志行：`[ctfy] report tools=['save_report']`）

---

## 5. 其余待办（按收益排序，做完 4 再看）

| # | 事项 | 为什么 | 大概工作量 |
|---|---|---|---|
| 1 | **软截止真生效** | 现在给 480s 就做满 481s，prompt 写「必须收敛」无效。要在 soft 触发后把工具集换成只剩 `submit_answer` / `finish` | 半天 |
| 2 | **技能硬约束** | 同一道题跑两遍，一次加载了技能一次没加载。要把 triage 决策表（约 1.1k token）内联进 system prompt | 半天 |
| 3 | **有技能/无技能 A/B** | 切换只需一行环境变量，差的只是跑量 | 跑量，不是开发 |
| 4 | **收口 `rt/src`** | agent 现在还能读到 `/var/ctf/jail/rt/src`，隔离不彻底 | 2 小时 |

---

## 6. 环境与常用命令

### 6.1 搭环境（跑任何东西之前）

```bash
cd strix-ctf-agent
./setup.sh        # 建 .venv + 装 124 个包，首次 1-3 分钟
./selftest.sh     # 五项离线自检，末行必须是「全部通过」
```

`setup.sh` 里有两个刻意的设计，**不要"优化"掉**：

- **源探测**：先花 3 秒探 `pypi.org`，不通就切清华镜像。直连时 `uv` 会静默挂死，
  表现是「卡住不动、.venv 只有 80K」，很难诊断。
- **`pip install --no-deps`**：`requirements.lock` 里有上游死结
  （`fastmcp 4.1.4` 声明要 `mcp>=2.3.0`，而实装 `mcp 1.30.0`），任何解析器都会拒绝。
  照单装才是忠实复现，那套组合实测能跑。换成正常 `pip install` 会解析失败。

### 6.2 跑测试

```bash
.venv/bin/python -m pytest -q          # 应该 75 passed
```

`pytest.ini` 已配好 `pythonpath = src vendor/src`，不用手动设 `PYTHONPATH`。

### 6.3 本地跑一题

```bash
export LLM_API_KEY=... LLM_API_BASE=https://.../v1 STRIX_LLM=openai/glm-4.6
PYTHONPATH=src:vendor/src STRIX_RUNTIME_BACKEND=local \
  .venv/bin/python scripts/run_strix_ctf.py --target http://10.0.0.5:8080 --turns 12
```

三种目标形态：

```bash
--target-kind web  --target https://...       # Web
--target-kind tcp  --target 10.0.0.5:1337     # 裸 TCP
--target-kind file --files-dir ./chal         # 附件
```

### 6.4 平台批量评测（要 root）

```bash
echo '<队伍 token>' > /root/.ctfy/token && chmod 600 /root/.ctfy/token
PYTHONPATH=src:vendor/src .venv/bin/python scripts/eval_sample.py \
  --ids SAMPLE-001 --out /tmp/r1.jsonl
```

必须 root，因为要被试 agent 的 shell 关进 mount namespace。不关的话它会 `cd /workspace`
翻仓库、从 `ps` 抄走 token 去打平台 API——实测单题烧 200 万 token，还把源码常量当 flag 交了。

token 走文件不走命令行参数，因为 `ps` 是全机器可读的。

### 6.5 构建与推送镜像

```bash
docker build -f docker/Dockerfile \
  --build-arg APT_MIRROR=mirrors.tuna.tsinghua.edu.cn \
  --build-arg PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ \
  -t strix-ctf-agent:1.0.0 .
```

**两个源参数国内必加。** 实测不加时 apt 索引一层要 **654 秒**，加了是 **9 秒**。

推送：

```bash
echo "$CTFY_TOKEN" | docker login registry.ctfy.io -u ctfy --password-stdin
docker tag strix-ctf-agent:1.0.0 \
  registry.ctfy.io/f0aef9e3-3b15-4648-8b7c-e1e3c1a01f79/strix-ctf-agent:v2
docker push registry.ctfy.io/f0aef9e3-3b15-4648-8b7c-e1e3c1a01f79/strix-ctf-agent:v2
```

### 6.6 镜像合规自检（改完必跑）

平台只认两条 blocking 判据，本地可以完整复现：

```bash
# 判据一：没有 task.json 也必须写出 result 文件
rm -rf /tmp/w1 && mkdir -p /tmp/w1 && chmod 777 /tmp/w1
docker run --rm -w /ctfy/work -e CTFY_WORK_DIR=/ctfy/work -v /tmp/w1:/ctfy/work \
  strix-ctf-agent:1.0.0
cat /tmp/w1/result.json          # 必须存在且是合法 JSON

# 判据二：dry_run + 自定义 result 路径
rm -rf /tmp/w2 && mkdir -p /tmp/w2/out && chmod -R 777 /tmp/w2
cat > /tmp/w2/task.json <<'JSON'
{"schema_version": 2, "dry_run": true, "run_mode": "instance",
 "challenge": {"name": "smoke"}, "scope": [], "result": {"path": "out/result.json"}}
JSON
docker run --rm -w /ctfy/work -e CTFY_WORK_DIR=/ctfy/work -v /tmp/w2:/ctfy/work \
  strix-ctf-agent:1.0.0
cat /tmp/w2/out/result.json      # 必须写在这个路径，不是默认位置
```

---

## 7. 踩过的坑（照这个躲，别自己再试一遍）

| # | 现象 | 根因 | 状态 |
|---|---|---|---|
| 1 | 模型请求 401，看着像 key 失效 | 平台注入 `LLM_BASE_URL`/`LLM_MODEL`，strix 读 `LLM_API_BASE`/`STRIX_LLM`，名字对不上 | 已修（`platform_env.py`） |
| 2 | engagement 题 0 秒结束，`stop_reason=no_target` | `scope` 是主机名，原逻辑只认 `http://` 开头 | 已修 |
| 3 | 提示词膨胀 8.5k token/次 | `register_skill_dir` 把 190 篇 md 全当技能注册，其中 178 篇是无 frontmatter 的参考子文件 | 已修（只注册 12 个索引） |
| 4 | 带附件的题 1.2 秒就崩，`mount: special device ... does not exist` | 子进程 `cwd` 不是仓库根，附件目录是相对路径，mount 按 cwd 解析 | 已修（全部 `resolve()`） |
| 5 | 提交返回 `instance_not_found` | 实例在 run 结束销毁，父进程事后补交 | 已修（sidecar） |
| 6 | 明明解出却判 FAIL | 拿实例级 `answered_correctly` 当判据，重拉实例后归零 | 已修（用队伍账本） |
| 7 | `docker push` 报 `denied`，但 token 明明有效 | 令牌的 registry `access` 是空数组——认得出人但没授权任何仓库 | 平台侧开镜像 write 权限 |
| 8 | `docker build` 卡在 apt 十几分钟 | 走 `deb.debian.org` 在国内极慢 | 加 `--build-arg APT_MIRROR=` |
| 9 | `pip install -r requirements.lock` 报 `No solution found` | fastmcp/mcp 版本死结 | 用 `--no-deps`，这是设计不是 bug |
| 10 | 镜像能起但平台判 `no_result_file` | 只往 stdout 打了 JSON | 结果必须写文件，`entrypoint.sh` 有三道保险 |

---

## 8. 红线：这些事不要做

1. **不要改 `vendor/src/strix/`。** 全部改造都在外层。改上游会让"升级 strix"变成 rebase 地狱，
   而且现在的 118 条测试是围绕"上游原样"写的。
2. **不要用 `answered_correctly` 判分。** 只用 `my_team_solved_question_ids`。这条踩过一次，
   把 8 道会做的题判成 FAIL。
3. **不要在父进程补交 flag。** 必须 run 内提交。
4. **engagement 模式下不要调 `POST /api/v1/instances`。** `target_instance` 非空就是在跑。
5. **不要擅自推送镜像。** 推 `v2` 之前先过 §6.6 两条自检，并告诉用户。
6. **不要动 token 文件、不要打印 token、不要把它写进任何会被提交的文件。**
   `/root/.ctfy/token` 权限必须是 600。
7. **不要并发起多个评测进程。** 队伍配额是 **1 个并发实例**，并发会互相挤掉并污染数据。
   我们犯过：三个进程同时跑，数据全废。

---

## 9. 怎么证明你改对了

改动完成时，按这个顺序自证，**不要跳过任何一步**：

```bash
# 1. 回归没退化
.venv/bin/python -m pytest -q                 # 期望：全绿，条数 >= 118（当前 118 passed, 1 skipped）

# 2. 离线自检没过期
./selftest.sh                                 # 末行：全部通过

# 3. 镜像仍然合规（改过 docker/ 或 src/ 就要跑）
#    见 §6.6 两条

# 4. 真的跑一次 engagement 假题
#    造一个 task.json：run_mode=engagement, target_instance=<假值>,
#    scope=["example.test"], questions=[]
#    期望：日志里有 PUT report 尝试，result.json 正常写出，stop_reason 正常
```

第 4 步是最容易被跳过、也最容易出问题的一步。前三步全绿但第 4 步炸的情况很常见——
因为前三条不碰网络和平台 API。

---

## 10. 现在的状态快照

| 项 | 状态 |
|---|---|
| 代码 | 118 条回归全绿（1 skip = 本机缺 `agents` SDK）；SAMPLE 套题 11/11 可测题通过 |
| 镜像 | `registry.ctfy.io/f0aef9e3-3b15-4648-8b7c-e1e3c1a01f79/strix-ctf-agent:v1`，886 MB，amd64，已推送 |
| digest | `sha256:2105671be072d975c30819617fda422dc2ca704014d31acc1f9157ed52a8990f` |
| conformance | 两项 blocking 判据本地全过 |
| GAUNTLET | ✅ 报告投递已实现（边做边存 / 收工钩子 / 空报告保护）；字段名待真机确认 |
| 镜像 vs 代码 | ⚠️ 已推的 `v1` **不含**本次改动；需重建 `v2`，推之前先过两条 conformance 并告知用户 |
| 平台账号 | 队伍并发实例上限 1；CYBENCH / SAMPLE 部分题曾解出（见 `reports/`） |

### 评测数据别误读

`reports/results.glm52.jsonl` 里 glm-5.2 表面 0/6，**但六题全部无效**：
两题实例未就绪、一题撞平台 404 窗口、两题超时、三题根本没跑起来。
同期平台从 14:51 起大面积 503。**这批数据不能用来评价模型能力。**

---

## 11. 如果你只有时间读三个文件

1. `src/ctf_strix/agent.py`（约 1000 行）—— 整个入口逻辑都在这
2. `docs/07-镜像提交路径.md` —— 镜像怎么来、为什么这么推
3. `reports/STATUS.md` —— 现状速览

其余的可以按需查。

---

*有疑问先看 `docs/01` 到 `docs/07`（决策记录），协议细节查 `docs/08`（原文）。*
