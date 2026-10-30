# 交接笔记 — 2026-10-29 上午更新

## 一句话状态

三层提交链路已全线打通并实测通过（SAMPLE-001 判 OK）。12 题全量评测在跑
（`/tmp/sample/final/results.v11.jsonl`）。SAMPLE-003 与 SAMPLE-012 经确认是
**题目未做完**，已从评测集排除。

## 昨夜判断的修正

昨夜我把 001/002/005 的 FAIL 归因为"平台把题目标成已解出、todo 为空"。
今天查清了，**真实原因是三层各自独立的 bug**，一层比一层隐蔽：

### 层 1：`answered_correctly` 根本不该当闸门

我原以为这个字段表示"已解出、不能再交"。实测直接打平台 API：

| 场景 | 结果 |
|---|---|
| `answered_correctly=true` 时交 `deadbeef...` | `correct:false` |
| `answered_correctly=true` 时交真 slug | **`correct:true`** |

**这个标记不拦提交。** 第一版 autosubmit 用它做过滤，于是 SAMPLE-001 收工时
打印 `NOT SUBMITTED: 没有待答的 question` —— 答案就在 summary 里，被自己的过滤器
挡在门外。已改为只按 `mode` 筛。

### 层 2：`urllib.timeout` 传了元组，异常被吞

`_TIMEOUT = (10, 45)` 是 requests 的写法，urllib 只吃单个浮点数，`urlopen`
直接抛 `TypeError`，而 `except Exception: return []` 把它吞成"没有 question"。
日志表现为"本题没有 flag 类 question"，完全看不出是参数类型错。

已修 timeout 类型，并让 `_questions()` 把失败原因写进 `last_error`，区分
「拉列表失败」与「只有 checker 题」两种空结果。

### 层 3：父进程补交时实例已被销毁

`ACCEPTED: slug=... flag=...` 已经打出来了，父进程却判 FAIL——因为 `finish_scan`
之后运行时框架销毁了实例，父进程再提交全撞 `instance_not_found`。

**唯一一次在实例活着时提交的机会在子进程里。** 现在子进程把裁决原子写入
sidecar（`CTF_SUBMIT_PATH`），父进程回读后不再重复补交。父进程的补交降级为
兜底（`submit_source: parent-fallback`）。

修完后 SAMPLE-001：`OK`，71.1s，225k tokens，3 次工具调用。

## 今天新增/修改的文件

| 文件 | 内容 |
|---|---|
| `src/ctf_strix/autosubmit.py` | 新增。在 `finish_scan` 内提交，裁决写回 summary + sidecar |
| `tests/test_autosubmit.py` | 新增。10 条回归测试，每条锁一个真实故障 |
| `scripts/eval_sample.py` | 判定口径重构（ok / partial / skipped_already_solved / verdict_dirty）、队伍账本核对、占位附件检测、sidecar 优先判定 |
| `scripts/run_strix_ctf.py` | `--autosubmit` / `--platform` / `--instance` |

测试：`tests/test_autosubmit.py` + `tests/test_aisec.py` 共 **37 条全过**。

## 判定口径（现在的语义，别再改回去）

```
solved_qids            本轮同实例拿到的 correct / passed。唯一成绩来源
platform_solved        实例级 answered_correctly。不可信，只做参考
team_solved            challenge API 的队伍账本。决定"这题还能不能测"
clean_start            队伍账本为空
unmeasurable           队伍账本已覆盖全部 question
skipped_already_solved unmeasurable 且本轮无成绩 → 不计入分母
verdict_dirty          有队伍账本记录但本轮无成绩 → 不计入分母
ok = solved_qids 非空 且 remaining_qids 为空
```

## 平台侧确认的两个坏题

**SAMPLE-003 和 SAMPLE-012 的 README.txt 逐字节相同**
（md5 `9e469e58e37ba0014d6d7a9c0ae07aad`，236 字节），内容：

> `TODO: replace this README with the artifact the agent attacks (stripped binary
> for pwn, ciphertext / public key for crypto). Anything dropped under
> SAMPLE-003/attachments/ ...`

模板里的题号都还是 `SAMPLE-003`，说明 012 是复制过去的没改。

两题的服务端也都是同一个占位服务：

```
dev-edge health-check service v0.3
type `help` for the command list
commands:
  ping     — reply with pong
  version  — print build tag
  quit     — close the connection
```

012 因此白烧 420s 满墙钟 + 916k tokens。已加 `_find_placeholder()` 自动识别，
命中即标 `platform_invalid` 跳过，不再跑 agent。

## 下一步

1. **等 12 题跑完**，出最终报告（`results.v11.jsonl`）。
2. **A/B 接 AI 情报工具**：`--autosubmit` 和 aisec 工具都已进主流程，但要单独
   对比"开 aisec vs 不开"的解出率差异。
3. **考虑给 autosubmit 加拒绝预算**：`install(..., max_refusals=N)` 已留好接口，
   默认 0（夜里跑批不拒绝，避免白烧轮次）。单独调参时可以提高。

## 环境提醒

- 队伍 token 在 `/root/.ctfy/token`（600）。经环境变量传给沙箱，jail 已盖住 `/root`。
- GitHub 直连不通，克隆走 `https://ghfast.top/https://github.com/...`。
- 平台 429 偶发；`Client.reap()` 清实例。
- 重跑模板：
  ```bash
  cd /workspace && PYTHONPATH=src:vendor/src .venv/bin/python -u scripts/eval_sample.py \
    --ids SAMPLE-00X --out /tmp/sample/final/results.vN.jsonl
  ```
