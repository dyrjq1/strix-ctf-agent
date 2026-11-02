# 17 · GLM-5.3-EV vs DeepSeek-V4.1-Flash 配对对比

> 日期：2026-10-31 夜（ABBA 第一轮）
> 用户要求：把 agent 模型换成 GLM-5.3-EV，与留存的 DeepSeek 数据比较，判断哪个更强。
> 结论先行：**不换模型**。修掉测量 bug 后两臂速度差只有 1.4x；095 的失败不是
> "模型不会"，而是工具面里缺一个"一次把变体打完"的调用。补上 `path_variants`
> 后 DeepSeek 在 095 上从 0/2 变成 2/2，且比 GLM 更快（详见 §9）。

## 1. 控制变量

比较的是模型，不是框架。除 `STRIX_LLM` 外全部固定：

| 变量 | 值 |
|---|---|
| 代码版本 | `616ca78`（两臂完全同一个 commit） |
| 供应方 | `https://llmapi.paratera.com/v1`（同一家，排除网关差异） |
| 模型 id | `openai/GLM-5.3-EV` / `openai/DeepSeek-V4.1-Flash` |
| 预算 | `--turns 30 --max-turns 30 --wallclock 600 --max-wallclock 600` |
| 并发 | **1 个实例串行**（比赛 `max_instances_per_team_effective=1`） |
| 工具面 | 同一套 `install_ctf_toolset()`（Caido/记账/子 agent 均已摘除） |
| 排序 | ABBA：074 G→D、083 D→G、064 G→D、095 D→G |

⚠️ 预算陷阱：`batch_eval.py` 按难度放大预算（medium×1.6、hard×2.3），
所以「`--turns 30`」在 hard 题上实际是 72 轮上限。两臂一致，不影响配对比较。

## 2. First round (SUPERSEDED -- see section 3)

| # | challenge | difficulty | model | solved | tools | agent wall |
|---|---|---|---|---:|---:|---:|
| 1 | 074 | hard | GLM | yes | 20 | 600.0s |
| 2 | 074 | hard | DeepSeek | yes | 9 | 39.6s |
| 3 | 083 | medium | DeepSeek | yes | 14 | 73.3s |
| 4 | 083 | medium | GLM | yes | 9 | 46.5s |
| 5 | 064 | medium | GLM | no | 30 | 424.8s |
| 6 | 064 | medium | DeepSeek | no | 38 | 338.3s |
| 7 | 095 | hard | DeepSeek | no | 29 | 600.0s |
| 8 | 095 | hard | GLM | yes | 8 | 72.2s |

On the surface: GLM 3/4 vs DeepSeek 2/4, but "GLM is 15x slower on 074".
**That conclusion was wrong.** See section 3.

## 3. A bug that poisoned every timing number (fixed)

### 3.1 How it surfaced

In the second round the 074/GLM log looked like this:

```
[scan]  id=...  turns=30
...
[done] 218.9s  result=RunResultStreaming        <-- already finished
[guard] reach=43 ... finish: refused=0 allowed=1  <-- finish_scan accepted
[usage] calls=22 in=1041311 out=13346 total=1054657

[WALLCLOCK TIMEOUT after 600s]                    <-- then 381s of nothing
```

`[done]` printed, so `run_strix_scan` had returned. But the process never
exited. The difference is the next line: `[deadline]` never appeared.

### 3.2 Root cause

`DeadlineGuard.snapshot()` called `should_kill()` **while holding**
`self._lock`, and `should_kill()` acquires the same lock. `threading.Lock` is
not reentrant, so the run deadlocked at the very last print.

Scope: **any run with `--soft-deadline > 0`**. Every such run hung at teardown
until the parent SIGKILLed it. Two consequences:

1. **Timings were wrong**: solved challenges were recorded as wall-clock
   timeouts.
2. **The conclusion inverted**: 074/GLM really took 62s but was recorded as
   600s, producing the "GLM is 15x slower" claim.

### 3.3 Fix

Take the lock, compute the state, release, then call `should_kill()`.
Regression: `tests/test_deadline_snapshot.py` -- 4 happy-path assertions plus 1
counter-example that reinstates the old implementation and asserts it
deadlocks within 1s in a worker thread, so the test cannot silently pass if the
bug returns.

Measured: new implementation returns in 0.03s; old implementation times out.

### 3.4 Re-run after the fix (these are the usable numbers)

| # | challenge | model | solved | tools | agent wall | solve | token |
|---|---|---|---|---:|---:|---:|---:|
| 1 | 074 | GLM | yes | 11 | **62.1s** | 72.8s | 350,322 |
| 2 | 074 | DeepSeek | yes | 14 | **42.9s** | 51.6s | 437,479 |
| 3 | 095 | DeepSeek | no | 26 | 600.1s | -- | 1,871,949 |
| 4 | 095 | GLM | yes | 21 | 252.6s | 263.9s | 1,014,368 |

**074 is a 1.4x difference, not 15x.** The first-round claim is withdrawn.

## 4. What actually reproduces (both rounds)

| measure | 074 / both rounds | 095 / both rounds |
|---|---|---|
| GLM solved | yes, yes | yes, yes (8/72s, 21/253s) |
| DeepSeek solved | yes, yes | **no, no** (29/600s, 26/600s) |

**095 is the only reproducible split: GLM 2/2, DeepSeek 0/2, with the same
failure shape both times.**

Read from `agents.db`:

- Round 1: locked onto "nginx/Express percent-decoding", 29 calls, never tried
  all-uppercase.
- Round 2: pivoted to raw-socket / edge-header bypass, wrote nine scripts
  (`bypass.py`, `raw.py`, `fuzz_internal.py`, `fuzz2.py`, `prefix.py`,
  `matrix.py`, `hdrs.py`, `go.py`, `oracle.py`), still never tried
  `/INTERNAL/banner`.
- Common shape: **it would rather build a more elaborate tool than send one
  more request with a different spelling of a path it already has.** That is
  exactly what `path_variants` (docs/18) removes from the model's hands.

## 5. Behaviour differences

| dimension | GLM-5.3-EV | DeepSeek-V4.1-Flash |
|---|---|---|
| speed on a known chain | same order of magnitude (074: 62s vs 43s) | slightly faster |
| enumeration across mechanism classes | **strong**, lays out many payload classes | weak, locks onto one hypothesis |
| behaviour on failure | keeps opening new directions | deepens the same one, or builds a bigger tool |
| tokens on a failed challenge | 1.01M (095 round 2) | 1.87M (095 round 2) |

## 6. Conclusions

1. **Do not switch models.** The split is not speed; it is **how wide the
   hypothesis space gets covered**. After the deadlock fix the speed gap is
   1.4x, which is not worth trading coverage breadth for.
2. **The 095 split reproduces (2/2 vs 0/2); 074 does not (2/2 vs 2/2).**
   If a model switch is made, make it on "needs several mechanism classes",
   not on difficulty.
3. **Better than switching models: turn "remember to try" into one call.**
   Round 3 confirms it: with `path_variants` installed, DeepSeek solved 095 in
   35.9s / 8 calls -- faster than GLM's 74.0s / 13 calls. See section 9.
4. **Still a small sample**: at most n=4 per cell, 064 unsolved by both
   (a skill-coverage gap, not a model gap).

## 7. Harness fixes validated this round

- `web_search` / `web_get_contents` are offline stubs (same name and schema,
  no network);
- soft deadline wired into the batch runner at 75% of the wall clock;
- **soft-deadline teardown deadlock fixed** (section 3);
- new `path_variants` primitive (docs/18).

## 8. Limitations

- 2 runs per cell: enough to say "same order of magnitude", not enough for a
  precise ranking.
- 064 fails for both models; the skill library does not cover that class.
- Each platform challenge is a fresh instance, so cross-challenge absolute
  seconds are not comparable.
- All data comes from the practice suite.

## 9. Round 3: after `path_variants`, the split closes

Same code, same budget (25 turns / 420s), one fresh instance per run:

| # | challenge | model | solved | tools | agent wall | solve | tokens | flag provenance |
|---|---|---|---|---:|---:|---:|---:|---|
| 1 | 095 | DeepSeek | yes | 8 | **35.9s** | 46.6s | 279,748 | `path_variants` |
| 2 | 095 | GLM | yes | 13 | **74.0s** | 84.8s | 601,943 | `http_probe` (after `path_variants` surfaced it) |
| 3 | 074 | GLM | yes | 18 | 119.6s | 128.7s | 802,924 | `exec_command` |
| 4 | 074 | DeepSeek | yes | 13 | 71.8s | 83.0s | 527,570 | `exec_command` |

**4/4 solved, no timeouts, no turn caps.**

### 9.1 Why this is causal, not noise

The DeepSeek 095 trace (`20261031-143426`) is 8 calls:

```
load_skill -> http_probe -> load_skill -> route_map
-> method_sweep -> path_variants -> http_probe -> finish_scan
```

and `path_variants` returned

```
200 GET [upper] /INTERNAL/BANNER | 57B | Release banner -- FLAG{...}
403 GET [as-is] /internal/banner
```

The tool fired exactly at the step where both earlier DeepSeek runs (29 and 26
calls) diverged into percent-decoding theories and raw-socket scripts. The GLM
run did the same, then spent 3 extra calls confirming with `http_probe` and
`think`.

### 9.2 What the two models are actually good at after the fix

| dimension | GLM-5.3-EV | DeepSeek-V4.1-Flash |
|---|---|---|
| total wall on 095 | 74.0s | **35.9s** |
| total wall on 074 | 119.6s | **71.8s** |
| tokens on 095 | 601,943 | **279,748** |
| tokens on 074 | 802,924 | **527,570** |
| verification habit | re-probes before submitting (good) | submits on first 2xx (faster, slightly riskier) |
| call efficiency | 13-18 calls | 8-13 calls |

DeepSeek is faster and cheaper on both challenges once the tool surface stops
forcing it to invent machinery. GLM's extra calls are mostly redundant
confirmation. **Neither difference is large enough to justify a model switch;
the tool surface was the bottleneck.**

### 9.3 Recommendation

Keep **DeepSeek-V4.1-Flash** as the production model (faster, half the tokens),
and keep `path_variants` in the tool surface as the load-bearing fix. If GLM is
ever preferred, do it for its verification habit, not its solve rate -- the
solve rate difference disappeared once the tool existed.

### 9.4 Honest limits

- n=1 per cell in round 3. 095 instances differ (fresh flag each launch), so
  absolute seconds are not strictly comparable across runs.
- Both models still fail 064 (`hard`). That is a skill coverage gap, not a
  model gap.
- All data is from the practice suite. Nothing here has been validated on the
  live competition set.
