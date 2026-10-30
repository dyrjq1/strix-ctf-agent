# 转换产物（自动生成，勿手改）

来源：ljagiello/ctf-skills（MIT，3.5k★）。由 `build_skill_pack.py` 生成。

## 用哪个技能

每类只有**一个** strix 技能，名字是 `<分类>/<分类>`：

```
load_skill("ctf-pwn/ctf-pwn")        # 拿 pwn 索引
load_skill("ctf-web/ctf-web")        # 拿 web 索引
```

索引里形如 `[heap-techniques.md](heap-techniques.md)` 的链接是**容器内路径**，
后续用 `read_file` 读，例如 `ctf-pwn/heap-techniques.md`。
**不要**把子文件当技能加载——它们没有 frontmatter，不是技能。

## 成本

| 技能名（load_skill 用） | 索引 tokens | 子文件数 | 目录体积 |
|---|---|---|---|
| `ctf-pwn/ctf-pwn` | 5233 | 65 | 1141.9 KB |
| `ctf-web/ctf-web` | 4303 | 23 | 580.6 KB |
| `ctf-crypto/ctf-crypto` | 10517 | 19 | 624.7 KB |
| `ctf-reverse/ctf-reverse` | 3983 | 22 | 525.4 KB |
| `ctf-forensics/ctf-forensics` | 9258 | 14 | 377.4 KB |
| `ctf-misc/ctf-misc` | 7105 | 13 | 289.2 KB |
| `ctf-osint/ctf-osint` | 2555 | 4 | 74.9 KB |
| `ctf-malware/ctf-malware` | 2272 | 4 | 54.6 KB |
| `ctf-ai-ml/ctf-ai-ml` | 1772 | 3 | 77.2 KB |
| `ctf-similar-search/ctf-similar-search` | 1614 | 0 | 19.8 KB |
| `ctf-triage/ctf-triage`（自建） | 1101 | 0 | 4.3 KB |
| `ctf-ai-infra/ctf-ai-infra`（自建） | 1836 | 0 | 7.2 KB |

> 两个自建技能不走构建器生成，重建时不会被覆盖：
> - `ctf-triage`：拿到未分类题目时的分流入口，2 分钟定型
> - `ctf-ai-infra`：AI 基础设施 / agent 框架的**实现漏洞**（SSRF、插件加载 RCE、MCP 投毒…）。
>   上游的 `ctf-ai-ml` 只覆盖模型对抗攻击，不覆盖这一类，而 TPCTF 的 AI 安全命题正是后者。

一次只加载**一个**索引（5k token 量级，`ctf-crypto` 例外，10.5k），
读完索引再按需 `read_file` 单个子文件。
全部 178 个子文件约 888k token，任何"预先全读"都会撑爆上下文。

## 接入 strix

```python
from strix.skills import register_skill_dir
register_skill_dir("/path/to/skills_strix")     # 全局一次即可

# 之后按需加载
load_skill("ctf-triage/ctf-triage")             # 先定型
load_skill("ctf-web/ctf-web")                   # 再进具体方向
```

