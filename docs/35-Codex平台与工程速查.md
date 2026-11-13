# Codex 平台与工程速查（2026-11-06 定稿）

> 读者：新窗口的 Codex（开发统筹角色）+ 未来任何接手的人。
> 你在 `C:\Users\rjq\Downloads\strix-ctf-agent`。本文 = 比赛规则 + 平台操作 + 工程/红线速查，浓缩自 CLAUDE.md、docs/11 台账（§4.70–4.74）、memory 实测。
> 有冲突时：平台 API 字段 > docs/11 台账 > 本文件 > 你的印象。

## 1. 赛程与硬规则（出处：平台 API + 手册，已实测核对）

| 项 | 值 |
|---|---|
| 初选赛 | **2026-11-15 10:00–20:00 UTC+8**（挂了就进不了正式赛 → 一切以它为 deadline） |
| 正式赛 | 11-21 / 11-22 每日 10:00–20:00；设 authoring_windows（agent 出题，我方空白） |
| 报名截止 | 11-13 20:00 UTC+8（两赛道同日，需审核，问队长确认已报） |
| 入围测试 | 注册 282 队 > 150 上限 → **11-14 大概率加测** |
| 断网 | `agent_internet=deny` 且 11-03 起 `internet_policy=deny`（人类也断网）。**一切按无外网设计** |
| 实例配额 | 1 队 1 实例（`max_instances_per_team_effective=1`）→ 必须串行 |
| 计分 | 动态积分：0/1 解 = 1000 分随解出队数下降，无血分，**早解有优势** |
| 交付 | 镜像注册运行（ghcr.io/dyrjq1/strix-ctf-agent，平台现挂 v2）；读 `task.json`，写 `result.json` |
| 无选择题 | 正式赛无选择题，选择题通道已下线 |
| 出题范围 | 智能体赛道仅限在线交互类（web/pwn/AI 安全）——crypto/rev/misc 离线附件在出题侧被排除 |
| 11-07 | 正式规则发布日，出来后第一件事是核对（PoE 在 Agent Track 是否存在、断网细则） |

## 2. 平台操作（MCP 是唯一合法查询入口）

端点：`POST https://ctfy.tsinghua.edu.cn/api/v1/mcp/`，JSON-RPC 2.0，头：
`Authorization: Bearer $PF_TOKEN`、`Content-Type: application/json`、`Accept: application/json, text/event-stream`。

**⚠️ SSE 陷阱（踩过）**：`tools/call` 返回**不关闭的长连接**，`urlopen().read()` 永久挂死。必须流式逐行读，**拿到第一条 `data:` 行即停**。

**⚠️ token 纪律**：token 不在仓库里。平台 token 在 `C:\Users\rjq\.claude\jobs\373a92d2\tmp\pt_team.txt`，GitHub PAT 在同目录 `gh_token.txt`。不写进任何 git 跟踪文件、不打进日志。judgment 死前先核对响应体（403 可能是 competition_required 漏带参，不是吊销）。

读端点（判断失败用）：
- `GET /api/v1/eval/runs?limit=50` / `/eval/runs/{id}` / `/eval/runs/{id}/llm-calls`
- `GET /api/v1/eval/batches/{batch_id}`、run 归档 `GET /api/v1/eval/runs/{id}/artifact`（gzip）
- openapi.json 公开在 ctfy.io/openapi.json，不用 auth
- 平台 `input_tokens` 只计非缓存部分；真实输入要看 llm-calls 里的 `cache_read_tokens`（缓存命中 ~99% 属正常）

判失败三步（顺序别乱）：①三连计数（relayed_calls / turns / tool_calls_made）②stop_reason ③run 归档里 stdout/agent-log。**统计工具调用看 agents.db 的 function_call 表，别看 strix.log（exec_command 走 shell 通道不打 "Invoking tool"）**。

提交 API（11-05 演练实测）：
- `POST /instances/{id}/answers` **不存在**（405）
- 验证：`POST /api/v1/instances/{id}/verify-answer`（不写记录）
- 正式提交：`POST /api/v1/submissions`（写记录 + 计榜）
- qa 题：`POST /api/v1/qa/submissions`（不同端点！）

实例（platform Intel）：
- 创建偶发 503 → **重试并复用已有实例**；带 competition_id（否则 403 competition_required）
- `access=vpn` 实例（host 形如 `*.internal`）：需 WireGuard，取 `GET /instances/{id}/vpn-config`；无 wg.exe 可用户态实现（参考 `ctf-collab\scratch\SAMPLE-004\wgtun.py`）
- 附件：per-team-artifact 先 start_instance 再 REST `GET /api/v1/instances/{id}/attachments/{filename}`；公共附件可能是诱饵（假货骗时间）
- 实例/会话结束即销毁（solve_env_mode destroy，解出 15 分钟）→ 提交必须在 run 内完成

## 3. 跑题（**必须 VM，串行**）

本地 Windows 只能写代码 + 单测。VM：`ssh rjq@192.168.38.130`，密码 `54qhdxrjq`（sudo 同）。项目 `/home/rjq/work/strix-ctf-agent`（非 git，sftp 传）。依赖 `pip install --no-deps -r requirements.lock`。

```bash
cd /home/rjq/work/strix-ctf-agent
export PF_TOKEN='...' LLM_API_KEY='...' LLM_API_BASE='https://llmapi.paratera.com/v1'
export STRIX_LLM='openai/deepseekv4.1falsh-1017' STRIX_RUNTIME_BACKEND=local
export LITELLM_LOCAL_MODEL_COST_MAP=True PYTHONPATH=$PWD/src:$PWD/vendor/src
echo '[{"id":"CTFARENA-009","difficulty":"medium"}]' > ~/plan.json
nohup .venv/bin/python scripts/batch_eval.py --plan ~/plan.json --turns 25 --wallclock 600 \
  --out ~/results.jsonl --token "$PF_TOKEN" > ~/run.log 2>&1 &
```

难度自动放大预算：easy=(turns,wall)、medium=(1.6x,1.5x)、hard=(2.4x,2.3x)。VM 代码可能落后本地（用前先同步 src/）；token 在 VM `/home/rjq/.pftoken` + `/home/rjq/.llmkey`。LLM key 平台 eval 批用 DeepSeek（llmapi.paratera.com），本地跑题可 dashscope——**平台 eval 批用不了 dashscope**（模型-端点映射冲突）。

## 4. 本地测试纪律（Windows 坑多）

```powershell
cd C:\Users\rjq\Downloads\strix-ctf-agent
set TMP=%CD\ctfwork\pt_x
set TEMP=%TMP%
New-Item -ItemType Directory -Force ctfwork\pt_x\base | Out-Null
.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider --basetemp=%TMP%\base
```

- 必须用 venv python（系统 python 缺 `agents` 模块）
- 基线：**734 passed, 4 skipped**（§4.71 后；低于此 = 回归）
- `--basetemp` 的父目录要**预先创建**（否则 FileNotFoundError 被误判成测试失败——11-04 踩过：576 passed/115 errors 全是环境错误）
- 本机 shell 吞引号：写脚本到 `ctfwork\*.py` 再跑，不用 `python -c`；调外部 CLI 用批处理文件
- 控制台 GBK：中文/emoji 用 `PYTHONIOENCODING=utf-8` 或写文件读
- 写文件纪律：临时文件 + `os.replace` + 锚点唯一性 assert（`pathlib.write_text(newline='\n')` 在 Windows 先截断再抛错，毁过 nonweb.py）

## 5. 红线（违反任何一条 = 改动作废）

1. **不改 `vendor/`**（一行不改）；扩展只走 `strix.agents.factory.register_agent_tools`；不 fork
2. 一次只改一处（接线类修复可合并）；改前备份 `backup/<slug>-<日期>/`，改后台账补节 + 回滚路径
3. **不许对着失败日志改 prompt 字符串**（看到卡 /admin.php 就写"试试 /admin.php" = 过拟合）
4. **不许用留出集调参**；`experiments/pools.json` 不可动；迁移测试 Y < 5pp = 过拟合判废
5. 预算不单独调（turns/wallclock/CTF_ATTEMPTS）必须依附能力改动
6. 命名测试：改动一句话描述不得出现题号/IP/具体路径/flag
7. token/flag 不进 git 跟踪文件；reference/ 和 traces/ 含真 flag 不外传
8. 不引入需要外网的工具（agent 运行时无外网）
9. codex exec **绝不传 `-s`**；非 git 目录加 `--skip-git-repo-check`
10. pytest 全绿 + >= 基线 = 验收门槛（"这批题全绿"不等于验收通过）

## 6. 代码地图（改哪里找哪里）

`agent.py` 官方入口（task.json→kind→装工具→result.json）｜`capabilities.py` 共享安装器｜`catalogue.py` 工具单一真值表｜`prompt.py` CTF system prompt｜`tool_trim.py` 裁 _BASE_TOOLS｜web 四原语 `http_probe/discovery/variants` + `traffic.py` 流量台账｜附件/TCP `file_triage.py`/`nonweb.py`｜`aisec/` AI 指纹+CVE（`web_cve.py`+`data/web_cve_*.json` 通用 web CVE 索引）｜守卫组 `enum_guard/journey_guard/finish_guard/sweep_guard/deadline_guard` + `guard_mount.py` 挂载｜`success_stop.py` 解出即停｜`deadline.py` 墙钟看门狗（双级）｜`error_policy.py` LLM 错误分流（凭证 fail-fast + 瞬时退避）｜`usage_meter.py` token 计量 + 单次输出止损｜`evidence.py` 证据链（self-echo 判定）｜`autosubmit.py`/`platform_env.py` run 内提交｜`skillpack.py` 技能路由｜`tcp_bridge/vpn/jail` 接入与隔离。

历史锚点（正向改动均留备份与台账节号）：§4.64 附件自取+解出即停 → §4.65 并行竞速（默认关） → §4.66 跨通道结构化判定+PoE 探测 → §4.68 附件三级降级链 → §4.69 exec_bridge → §4.70 error_policy → §4.71/4.72 看门狗双级+加固 → §4.73 self-echo → §4.74 输出止损。

## 7. 当前状态（2026-11-06 快照）

- 本地 HEAD `affabb6`（工作树有未验收改动：agent.py + test_stop_state.py，review-package-20261105/ 含 8 问裁决）
- 平台 agent 注册 = **v2**；v2 批 15 题 8 解，v3 已有三码归因闭环
- 平台成绩：CTFARENA 已测 48/115 解 40（练习赛数字，不可外推正式赛）
- Docker 镜像本机不可构建（无 docker/WSL）只能 CI（GitHub Actions → ghcr，PAT 已入 token 文件）；CI 假绿已修（§4.61），镜像内 pytest 是真跑
- VM 代码落后本地一大截，同步窗把 src/ 推上去
- 攻坚空白：agentic_ai（043/047）、认证类（020/021）、设计缺陷（017/018）、供应链（064）、多网络（049）
- 【留出集封印】诊断/迁移批选题前先查 `experiments/pools.json` 归属；若你手头的题库列表来自 memory 提到过的「方差批/校准批」，先问我确认没踩封印

## 8. 遇到坑直接对号（全部实测）

| 症状 | 根因/修法 |
|---|---|
| 新窗口 shell 全拒「classifier unavailable」 | auto-mode 分类器模型超时；settings.json 已换 glm-5.2-fast-preview + codex/curl/git push 白名单（2026-11-05 修） |
| pytest 大量 FileNotFoundError | basetemp 父目录没建（见 §4） |
| `python -c "..."` 报错 | 本机引号拆坏，写 .py 文件再跑 |
| MCP 调用永久挂起 | SSE 不关流，读第一条 data: 即停（见 §2） |
| POST /instances/{id}/answers 405 | 端点不存在，用 /api/v1/submissions（见 §2） |
| 起实例 403 | 先核对响应体是不是 competition_required（漏 competition_id） |
| 起实例 503 | 平台容量，重试复用已有实例 |
| run 列表 input_tokens 只有几百 | 正常，平台只计非缓存（见 §2） |
| 平台 run cancelled + exit_137 | 历史根因「解出不停跑」已修（§4.64）+ 信号判定（§4.66/4.67）；新发先看三连计数 |
| run 归档 stdout 0 行 | 历史采集缺失常态，不能当容器没跑的证据 |
| unservable/access_unavailable | 平台侧接入容量问题（agent 从未启动），重试即好，别改代码 |
| git push 卡死 | DNS 污染，IP 直连：`git -c http.curloptResolve=github.com:443:140.82.112.4 push`（备选 20.27.177.113） |
| 附件 403 | eval-run 容器 token 在 challenges 级 REST 被拒 → 走 MCP 通道或降级链（§4.68） |

## 9. 派单/回报格式（与 Codex 协作的固定协议）

派单六项：目标（一句话可验证）/ 背景（路径，不复述）/ 范围（允许改哪些文件，禁 vendor）/ 验收（具体命令+期望）/ 红线（本单特别注意）/ 回报（文件清单+测试前后数字+消融+未做部分）。
Codex 派单模板：`cmd /c "codex exec --skip-git-repo-check -C <dir> -o out.md - < brief.txt > log.txt 2>&1"`，绝不传 `-s`。完整模板：CLAUDE.md §10；验收八条：CLAUDE.md §11。

## 10. 三条最优先建议（新窗口 Codex 先做这个）

1. **开测第一步 = §4 的 pytest 全量**：734 passed = 代码基线健康确认，连测试环境都搭不好就别谈别的。
2. 测试通过后读 CLAUDE.md §16 待办序：task8 已完（§4.71/4.72）+ Q6/Q7 已完（§4.73/4.74）→ 下一步 **v6 镜像 + 三路径终局冒烟**（正常解出 / PoE verify_exploit / 干净失败）。工作树里未验收的 agent.py 改动先验收再进镜像。
3. **11-15 初选赛是唯一真 deadline**：一切动作以「单实例串行稳定 + result.json 落盘 + 墙钟熔断」为优先；能力扩展全部让路。
