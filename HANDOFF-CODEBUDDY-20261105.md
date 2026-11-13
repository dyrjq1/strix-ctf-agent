# CodeBuddy 接入报告（交接给新窗口）

> 2026-11-05 · 写作背景：人机协同赛道（清华场）花名册调整——CodeBuddy 顶替 WorkBuddy 的位置。
> 结论先说：**可用，但必须按本文的调用方式来**。默认调用方式会在权限门上空转浪费轮次。

---

## 1. 是什么、什么角色

- CodeBuddy CLI（版本 2.179.2），腾讯出品的命令行 agent，能力形态与 Claude Code 类似：`-p` 非交互模式、`--model` 选模型、`--add-dir` 给目录访问。
- 可选模型：deepseek-v4.1-flash / glm-5.3 / kimi-k3.1-pro / minimax / step 等。本地跑通用 **deepseek-v4.1-flash**。
- 在花名册中的位置：**解题工位之一**（原 WorkBuddy 槽位）。Claude 调度、Codex 主力、CodeBuddy 独立攻坚单题。

## 2. 正确的调用方式（照抄即可）

**不要在 PowerShell 里内联调用**（嵌套引号会被拆坏，`Bash(python:*)` 会被当成命令执行报错）。
**用批处理文件**，结构如下（参考 `ctfwork\cb-dispatch-s004.bat`）：

```bat
@echo off
cd /d C:\Users\rjq\Downloads\strix-ctf-agent\ctfwork
codebuddy -p --allowedTools "Bash(python:*),Bash(python3:*),Bash(curl:*),Bash(openssl:*),Write" --model deepseek-v4.1-flash --add-dir C:\Users\rjq\Downloads\ctf-collab < 任务brief.txt > 输出日志.txt 2>&1
```

调度侧（我）用 `Start-Process` 或 `cmd /c` 后台跑批处理，完成后读日志验收。

- 任务 brief 写进 txt 文件，从 stdin 喂入；任务里要钉死回报格式（`[回报] 题号/状态/flag/解法/证据/耗时`）。
- `--add-dir` 指向 `C:\Users\rjq\Downloads\ctf-collab`（战场目录，token 在 `cb-token.txt`、scratch 区在 `scratch\<题号>\`）。
- 给它设止损（如 45 分钟），brief 里写明。

## 3. 权限配置（三个坑，全部实测）

1. **settings.json 的 `permissions.allow` 在 `-p` 非交互模式下不生效**。已在 `C:\Users\rjq\.codebuddy\settings.json` 写过白名单（Bash(python:*) 等），第 2 轮照样全拒。不要指望它。
2. **`--allowedTools` 只认逗号分隔**。空格分隔会被静默忽略（第 3 轮因此失败且无任何报错）。正确写法：`--allowedTools "Bash(python:*),Bash(curl:*),Write"`。
3. **非交互模式下没有权限弹窗**：任何不在白名单里的工具（Bash 其他命令、Edit、内部工具）一律直接拒绝，模型会浪费轮次尝试后放弃。

最小验证命令（换机器/升级后先跑这个）：
```bat
codebuddy -p --allowedTools "Bash(python:*),Bash(curl:*)" --model deepseek-v4.1-flash < 一个要求跑python --version的txt > out.txt 2>&1
```
输出 `Python 3.14.6` 即链路通。

## 4. 当前白名单范围（用户 2026-11-05 批准）

`Bash(python:*)`, `Bash(python3:*)`, `Bash(curl:*)`, `Bash(openssl:*)`, `Write`

**扩大范围（含 `-y` / `--permission-mode bypassPermissions` / 裸 `Bash`）必须先问用户**——调度侧权限系统同样会对这些操作拦卡，属有意设计。

## 5. 已知行为特性

- **偏好走内部工具**：第 4 轮它放着放行的 Bash 不用，去调内部 `DeferExecuteTool`（延迟执行），被拒后直接停。**任务 brief 里必须写明「只用 Bash 执行命令，禁用延迟/后台执行工具」**（已加进 `cb-s004-brief.txt` 的执行纪律段）。
- **代码能力过关**：第 2 轮全程被权限挡、零命令执行的情况下，仍写出 13KB 完整 Vaudenay padding-oracle 攻击脚本（`ctf-collab\scratch\SAMPLE-004\solve.py`，纯标准库，start/probe/attack/submit/stop 五个子命令，hex/b64/raw 编码自适应 + TLS SNI 支持）。分析-编码能力不弱于预期。
- 诚实度好：拿不到结果会明确报 blocked 并说明原因，不臆造 flag。
- 它的 MCP 配置里有 sheetagent/weixinpay 等无关服务，但没有平台 CTF MCP——平台操作必须靠 brief 里写清 REST 调用方法 + token 位置。

## 6. 测试记录（SAMPLE-004，crypto padding oracle）

| 轮 | 调用方式 | 结果 |
|---|---|---|
| 1 | `-p` 裸调用 | 全部执行工具被拒（非交互无弹窗） |
| 2 | settings.json 白名单 | 仍全拒；但产出完整 solve.py + NOTES.md |
| 3 | `--allowedTools` 空格分隔 | 静默忽略，仍全拒 |
| — | 逗号分隔最小验证 | ✅ `python --version` 成功执行 |
| 4 | 逗号分隔正式派单 | Bash 已可用，但模型自选调 DeferExecuteTool 被拒后停止 |
| 5 | 逗号分隔 + brief 内执行纪律段 | **✅ SOLVED**（36:05） |

**第 5 轮验收结论（终局）**：CodeBuddy 端到端独立解出 SAMPLE-004（crypto medium）。
- flag `FLAG{e31bdebd…e3d2}`，平台 `submissions` 返回 `correct:true, challenge_fully_solved:true, ranked:true`，solve_time 489.3s
- 题面标注 padding oracle，实际是 ECB 前缀注入——CodeBuddy 自行识破并改打法（byte-at-a-time，3347 查询 16.6s）
- 实例 `access=vpn`、本机无 WireGuard 客户端——CodeBuddy 用 `cryptography` 库**自行实现用户态 WG 握手 + 最小 TCP/IP 栈**打通内网。这是超出预期的接入能力
- 证据链完整：33 个工作文件 + EVIDENCE.md 取证摘录 + run.log，留痕合规
- **花名册定稿：CodeBuddy 正式顶替 WorkBuddy 解题工位**（用户 11-05 拍板，本报告为验收依据）

**第 5 轮附带产出的平台情报（重要，已写进 COMBAT-BRIEF）**：
1. `POST /instances/{id}/answers` 不存在（405）；正式提交走 `POST /api/v1/submissions`，验证走 `verify-answer`
2. `access=vpn` 类实例需 WireGuard；平台提供 `/instances/{id}/vpn-config`；无 wg.exe 时可用户态实现（参考 `scratch/SAMPLE-004/wgtun.py`）
3. MCP `tools/call` 是不关闭的 SSE 长连接，`urlopen().read()` 会永久挂起——必须流式读到第一条 `data:` 即停
4. 起实例偶发 503，需重试并复用已有实例

## 7. 与 WorkBuddy 的交接状态

- WorkBuddy 实测：通道通、0 解出（SAMPLE-004 issue #6 仍 open），已评估为「仅验证了通道」。
- CodeBuddy 接管后，GitHub issue 派单协议不变（`[派单]`/`[回报]` 格式），CodeBuddy 的任务由 Claude 直接 stdin brief 派发，不走 GitHub（它没有 repo watcher 能力）。
- `docs/34-协同作战编排.md` 花名册段需要同步更新（CodeBuddy 替换 WorkBuddy，调用方式指到本文件）。

## 8. 红线（不变）

- token 不进任何 git 跟踪文件、不打进日志。
- 不用 `-y` / bypassPermissions，除非用户明确批准。
- CodeBuddy 是**本机解题工位**：靶机接入靠它自己 curl/python 打平台 REST；不要假设它有平台 MCP。

## 9. 遗留

- 第 5 轮 SAMPLE-004 端到端结果（若解出：补充 flag 证据 + 花名册正式定稿；若再败：归因是模型选路还是工具门，考虑换 kimi/glm 模型重试一轮）。
- `docs/34` 的花名册更新。
- WorkBuddy issue #6 处置（关闭或转 CodeBuddy）。
