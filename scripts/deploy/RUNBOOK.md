# 初选赛开赛 runbook（2026-11-20 10:00 UTC+8）

> 这份文件的唯一目的：把「开赛那 10 小时里能毁掉成绩的事」排在开赛前做完。
> 依据 docs/47 §1.5 的部署契约；规则出处见 docs/47 §1 的 F 编号。

## 0. 一句话时间线

| 时刻 | 做什么 | 谁 |
|---|---|---|
| 11-19 前 | `agent_run.sh --check` 在比赛 VPS 上全绿 | 用户 |
| 09:00–09:30 | WireGuard 起来，`wg show` 有 handshake，靶网段能 ping | 用户 |
| 09:30–09:50 | `install.sh` 装服务；`--check` 复跑；空跑一次真实例 | 用户 + Claude |
| 09:50–10:00 | 看板与 token 就位，不许在 10:00 之后动任何配置 | 用户 |
| 10:00 | 开赛，服务自己跑 | — |
| 每个整点 | 看三行：车道数 / 已提交题数 / 最近一次平台错误 | Claude |
| 19:45 | 停止接新题（`--until` 自动收），确认在跑的都收尾 | 自动 |
| 20:00 | 窗口关闭，实例被删；补交必失败（F13 提交窗口 300s） | — |

## 1. 开赛前 30 分钟：WireGuard（最容易在前 30 分钟崩的那一环）

交互式题（Web/Pwn）唯一接入方式是 WireGuard（F12）。它有两个已知坑：

1. **CAP_NET_ADMIN 未确认**。如果 `ip link add wg0 type wireguard` 报 `Operation not permitted`，
   说明容器没有该 capability：换一台 VPS 或用 host 网络，不要在开赛后现场修。
   验证：`ip link add wgtest type wireguard && ip link del wgtest`（两秒，不碰现有隧道）。
2. **DNS 不走隧道**。靶机名要显式用 `--dns` 或写进 `/etc/hosts`，否则解析到公网或直接失败。

```bash
wg show                     # 每条隧道都要有 latest handshake，不是 just "interface up"
ip route | grep -E 'wg|10\.' # 靶网段要在路由表里
```

## 2. 开赛前 30 分钟：网关

- `LLM_API_BASE` 必须是平台网关，不能是第三方中转站（F11 / QA#79）。`agent_run.sh --check`
  会拦 `paratera`/`siliconflow`/`openrouter` 这几种串。
- 网关要求显式 `max_tokens`（2026-11-14 实测：缺参全 400，报文还会误导成"参数非法"）。
  `agent.env.example` 里 `LLM_MAX_TOKENS=4096` 就是为这个。
- 验证一条：`curl -sS "$LLM_API_BASE/chat/completions" -H "Authorization: Bearer $LLM_API_KEY" \
  -H 'Content-Type: application/json' -d '{"model":"'"${STRIX_LLM#openai/}"'","messages":[{"role":"user","content":"hi"}],"max_tokens":16}'`
  —— 200 且 `choices` 非空才算通。**不要把 key 打进 shell 历史**：用环境变量，命令写进 `.env` 里跑。

## 3. 装服务

```bash
cp scripts/deploy/agent.env.example ~/.ctfy/agent.env
chmod 600 ~/.ctfy/agent.env
vi ~/.ctfy/agent.env          # 填 token / competition id / 网关
bash scripts/deploy/agent_run.sh --check     # 必须全绿
bash scripts/deploy/install.sh               # 装 systemd user unit 或 cron @reboot
```

`install.sh` 在装之前会跑一次 `--check`，不过不装 —— 装一个起不来的服务等于没装。

## 4. 重启演练（开赛前必做一次，10 分钟）

平台只保证**工作目录**跨重启保留（F9），且最多 3 次重启。所以要验证的是
"重启后不会从头再来、不会重复提交、不会双开跑同一题"：

1. `systemctl --user restart ctfy-agent`（或 `pkill -f compete.py`，让启动器自己拉起来）。
2. 看 `~/ctfy-logs/supervisor.log`：应当出现新的 `启动：...`，而不是第二个进程同时跑。
3. 看 `~/ctfy-state/`：状态文件在，说明进度没丢。
4. 平台上 `list_instances` 里没有两条属于本队的僵尸实例。

**这一步宁可在 09:50 做，也不要在 12:00 出了问题现场做。**

## 5. 赛中每整点看三行

```bash
ls ~/ctfy-state/                      # 有状态 = 在跑
tail -n 40 ~/ctfy-logs/compete-*.log | grep -E 'submit|flag|error' | tail -5
pgrep -fc 'compete.py'                # 应当等于 CTFY_LANES
```

判据：
- 进程数 < 车道数超过 2 分钟 → 启动器有问题，看 supervisor.log。
- 日志里连续出现同一条平台错误 → 记下来，10 分钟不变就换车道。
- 某题跑了 2 倍墙钟还没收 → 不正常，但要等本轮结束再动（杀进程会丢结果）。

## 6. 赛后被问到"为什么这题没解出"要有账

`result.json` / 日志要能回答：这题解到哪一步、为什么停。没有这条账的失败，
在复盘里和"没跑"无法区分 —— 这是 2026-11-15 forensics 里 69.7% 失败落在
"从未解出"组却说不清原因的直接来源。

## 7. 回滚

- 部署层：`bash scripts/deploy/install.sh --uninstall`，然后手动 `bash agent_run.sh`。
- 代码层：代码在 `CTFY_ROOT` 的 git 里，`git log` 找上一个 tag；**不要在赛中 pull**，
  所有代码变更在开赛前冻结。
- 环境层：`~/.ctfy/agent.env` 改坏了就从 `agent.env.example` 重抄。