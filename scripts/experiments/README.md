# scripts/experiments —— 实验工具（VM 侧跑）

这些脚本原本写在会话临时目录里，任务结束就会被清掉；搬进仓库是因为它们可复算：
每个结论都要能拿一条命令重跑出来。**全部只读**（除了 `ab_run.sh` 会真跑题、`fix_crlf.py` 会改文件），
按 `/home/rjq/...` 的 VM 路径写死，本地跑不了。

| 脚本 | 用途 | 典型用法 |
|---|---|---|
| `ab_run.sh` | 烧题 A/B 驱动：两臂同模型同预算，控制臂用环境变量关掉被测开关，串行 | `nohup bash ab_run.sh > ~/ab_run.out 2>&1 &` |
| `ab_analyze.py` | 按预注册判据打分（失败题调用中位降幅 ≥15% + 解出数不降） | `python3 ab_analyze.py` |
| `stall_from_logs.py` | 从各 run 的 `run.log` 回捞 `\| stall:` 后缀（JSONL 行里可能没有） | `python3 stall_from_logs.py 0` |
| `replay_today.py` | **仪表自检**：把某批 run 的 `agents.db` item 流逐条喂给真守卫，与线上打印值对账 | `python3 replay_today.py` |
| `replay_shape_sig2.py` | 离线形态判据扫描（历史总体，多阈值、多签名变体） | `python3 replay_shape_sig2.py` |
| `source_leak_gap.py` | 第 0 步：源码泄漏三段落差（请求过 → 200/404/兜底 → 是否转化），按行归属状态码 | `python3 source_leak_gap.py`（写 `~/source_leak_gap2.json`） |
| `output_truncation_audit.py` | P5 前提：历史输出里截断/落盘计数，以及落盘后有没有被回读 | `python3 output_truncation_audit.py` |
| `output_size_audit.py` | P5 前提：输出体积分布（上限 2000 行 / 50KB，见 vendor settings） | `python3 output_size_audit.py` |
| `untouched_audit.py` | 审计还剩多少题没跑过（pools.json 会过期） | `python3 untouched_audit.py` |
| `s3_pick.py` | 按预注册哈希规则选 20 题 + 3 个 spares | `python3 s3_pick.py` |
| `vm_pytest.sh` | VM 上跑 pytest（设好 TMP/TEMP/PYTHONPATH 与 basetemp） | `bash vm_pytest.sh s2v tests/test_enum_guard.py` |
| `fix_crlf.py` | 字节级去 CRLF，**替代 scp 后的 `sed -i 's/\r$//'`**（那条会吃掉行尾 r） | `python3 fix_crlf.py <文件>` |

**纪律**：跑 A/B 之前先看 `docs/32` §9 的预注册判据；跑完先跑 `replay_today.py` 做仪表自检，
确认被测机制真的被触发过再读判据（2026-11-15 的 S2 就是判据"通过"但机制零触发）。