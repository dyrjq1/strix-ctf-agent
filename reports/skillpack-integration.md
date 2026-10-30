# strix CTF 能力包 v1.0 接入记录

> 交付物：`strix-ctf-v1.0-20261029.tar.gz`（15 MB / 2966 条目）+ 交付说明
> 接入日期：2026-10-29 · 接入后回归：62 条测试全绿 · 端到端：SAMPLE-001 79.1s 解出

## 一、核对结论

包的 `selftest.sh` 在干净目录跑过，五项全绿：

| 项 | 结果 |
|---|---|
| 版本表达式求值器 | 11/11 断言 |
| 规则库完整性 | 163 指纹 / 147 组件 / 2581 条规则 / 求值异常 0 |
| 4 个 mock 靶场 | ollama 0.1.29 · gradio 4.44.1 · dify 0.6.9 · comfyui 0.3.27 全部识别 |
| CVE 匹配 | ollama 0.1.29 → 27 条 |

**规则库与我们的引擎 schema 完全对齐**，直接投喂即可用，无需转换：

```
ollama 0.1.29   -> 27 条    gradio 4.44.1 -> 19 条
dify   0.6.9    -> 25 条    comfyui 0.3.27 -> 9 条
```

## 二、与交付说明的三处偏差（按说明书接会踩）

### 1. `register_skill_dir(整包路径)` 会把 145 条塞进提示词

说明书 1.1 节写的是：

```python
register_skill_dir("/opt/strix-ctf/aisec/skills_strix")
```

按这个接，实测 `get_available_skills()` 返回 **145 条**、`<available_skills>` 块
25,400 字符（≈8.5k token）。原因是 strix 把注册目录里**每个 `<分类>/*.md`** 都当技能，
而包里 190 个 md 中只有 12 个是索引，其余 178 个是没有 frontmatter 的参考子文件——
它们进 prompt 只占位、零信息量，而且 prompt 是**每个 agent、每次调用**都要付的钱。

**改为只注册 12 个索引**（`src/ctf_strix/skillpack.py`）：

```
注册整包  145 条 / ~8.5k 字符（含 strix 自带 65 条）
只注册索引  12 条 / ~3k 字符
```

### 2. 子文件的相对路径在我们的容器里不存在

说明书写"用 `read_file` 读，例如 `ctf-pwn/heap-techniques.md`"——那是**背包根**相对的。
我们的 agent 工作目录是 jail 里的空 box，按 cwd 解析必然 404，而模型猜路径一次就是一轮。

**处理**：每个索引装载时在 frontmatter 之后插一行绝对路径提示，指向 jail 内的 bind 挂载点：

```
> 子文件目录：`/var/ctf/jail/skills/ctf-web/`。索引里 `[x.md](x.md)` 形式的引用，
> 用 `read_file` 读 `/var/ctf/jail/skills/ctf-web/x.md`；**子文件不是技能**，
> 不要用 `load_skill` 加载。一次只加载一个方向索引。
```

插在 frontmatter 之后而不是文件开头：strix 用 `^---` 锚定 frontmatter，插到最前面会让
`name`/`description` 解析失败，技能就变成"无名"。

### 3. `load_skill` 的参数是 list，不是位置参数

说明书 1.1 写 `load_skill("ctf-triage/ctf-triage")`。实际签名是
`load_skill(ctx, skills: list[str])`，且一次最多 5 个。分流提示里已改成 list 形式。

## 三、接入改动

| 文件 | 改动 |
|---|---|
| `src/ctf_strix/skills_strix/` | 新增 4.1 MB：12 分类 / 190 md |
| `src/ctf_strix/skillpack.py` | 新增：只暴露索引、注入路径提示、生成分流指令 |
| `src/ctf_strix/aisec/data/` | 新增 11 MB：163 指纹 / 147 组件 / 2581 规则 |
| `scripts/run_strix_ctf.py` | 启动期注册技能 + 把分流指令拼进 `user_instructions` |
| `scripts/eval_sample.py` | jail 内 bind 技能包与规则库，注入 `CTF_SKILLS_REF` / `CTF_AISEC_DATA` |
| `tests/test_skillpack.py` | 新增 21 条：索引集合、frontmatter 位置、266 条相对链接、分流提示 |
| `tests/test_aisec_data.py` | 新增 4 条：规则库条数与四个已知组件的 CVE 数 |

启动日志实测：

```
[aisec] registered 3 tools: ai_fingerprint, ai_cve_lookup, ai_quick_scan
[aisec] rules=/var/ctf/aisec allow=(none)
[skills] registered 12: ctf-ai-infra/..., ctf-triage/ctf-triage, ctf-web/ctf-web, ...
[skills] ref=/var/ctf/jail/skills
```

## 四、顺手修掉的一个真 bug

端到端复跑第一枪直接挂在 1.2 秒：

```
mount: /var/ctf/jail/rt/files: special device reports/files/SAMPLE-001 does not exist
```

根因：子进程是 `Popen(..., cwd=box)` 起的，**cwd 不是仓库根**，而附件目录是相对路径
（`reports/files/SAMPLE-001`）。mount 按 box 解析 → 源不存在 → `set -e` 中断整次启动，
还被记成一次 FAIL。

这个坑只在"题目带附件"时触发，所以之前 11 题全过也没暴露。已把 `out_path` 与附件
bind 源全部 `resolve()` 绝对化。

## 五、验证证据

| 验证 | 结果 |
|---|---|
| 包自测 `selftest.sh` | 全部通过 |
| 我们引擎吃新规则库 | 163/147/2581，四组件 CVE 数与包自测一致 |
| 指纹识别（我们引擎 + 4 个 mock） | gradio 4.44.1 / dify 0.6.9 / comfyui 0.3.27 / decoy 0 命中 |
| 技能注册 | 12 条索引，`ctf-triage` 可 load，路径提示在正文首行 |
| 工具层实测 | `load_skill(["ctf-ai-infra/ctf-ai-infra"])` 返回 3.4k 字符正文（一次性跑通） |
| jail 内可见性 | `/var/ctf/jail/skills/ctf-web/ctf-web.md` 可读 |
| 回归测试 | 62 条全绿（原 37 + 新 25） |
| 端到端 | SAMPLE-001：79.1s / 231k token / 4 次调用 / in-agent 提交，两个 question 全过 |

## 六、已知问题

1. **模型不总是听"先加载技能"这句指令**
   两跑同一道 mock 题（明确写了"第一步必须 load_skill"）：一次真的加载了
   `ctf-ai-infra`（正文 3.4k 字符进上下文，随后直接走 ai_quick_scan + 定向探针），
   一次完全跳过、开局去 `find /` 找 CVE 规则文件。
   
   这说明技能是"可得"而不是"必用"。和枚举守卫是同一个教训：**prompt 里的顺序约束
   会衰减**。要稳定生效得用硬约束（比如首轮工具结果里注入"你还没加载 triage"），
   或者干脆把 triage 的判决表内联进 system prompt（1.1k token，做得到）。

2. **覆盖率报告会把自定义技能折叠成 `custom`**
   `skills.__init__._track_skill_loaded` 对非 builtin 技能一律记 `custom`，
   strix 的 coverage 报告里看不出模型到底加载了哪个 CTF 方向。要看清只能翻运行日志。

3. **`ctf-crypto` 索引 10.5k token**
   单次加载就吃掉 1/6 的上下文预算。分流提示里已限制"一次只加载一个"，但没有硬约束
   （同第 1 条）。

4. **gradio mock 有低置信度误报**
   `text-generation-webui` 以 `low` 置信度同时命中。不影响主判定（high 优先），
   但会给 agent 多一条待查线索。

5. **agent 仍能读 `/var/ctf/jail/rt/src` 与 `/var/ctf/aisec`**
   技能子文件走独立 bind 是为了不逼它去翻源码目录，但 rt/src 仍挂在那里
   （Python 要 import），规则库又是个可读目录。两者都不算泄密（技能与规则本就是
   要给它的），但"可读范围"比设计意图大。彻底收口要等下一轮隔离加固。

6. **`ref_root()` 踩过一次空挂载点**
   宿主侧 `/var/ctf/jail/skills` 是空目录（bind 只在 namespace 内生效），
   原实现只判 `is_dir()`，本地调试时把路径提示指向了一个空目录。已改成"看目录里
   有没有分类子目录"，并补了回归测试。


## 七、下一步

**技能 A/B 对比**：同一批题跑两遍（有技能 / 无技能），比通过率、轮次、token。
现在两边都能一键切换（`CTF_SKILLS_REF` 置空即等于禁用技能注册），差的就是跑量。
建议先挑 3 道 AI 安全方向的题——技能包里有自建的 `ctf-ai-infra`，正是上游空白的那块。
