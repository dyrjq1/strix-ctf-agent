# 来源与署名

本包包含两份第三方作品，均为**修改后分发**（格式转换），按各自许可证要求在此声明。

---

## 1. CTF 技能库 — MIT

- 上游：https://github.com/ljagiello/ctf-skills
- 版权：Copyright (c) 2026 Lukasz Jagiello
- 许可证：MIT，全文见 `LICENSES/ctf-skills-MIT.txt`（副本亦在 `src/ctf_strix/skills_strix/LICENSE`）
- 修改内容：`build_skill_pack.py` 将各技能目录下的 `SKILL.md` 额外复制一份为 `<分类>/<分类>.md`，以符合 strix 加载器的 `<分类>/<名字>.md` 硬编码路径约定；未改动任何原文内容。
- 本地基线 commit：`2388a3b`

`ctf-triage/` 与 `ctf-ai-infra/` 两个技能为本项目自建，不在上述 MIT 授权范围内。

---

## 2. AI 基础设施漏洞规则库 — Apache-2.0

> **Based on Tencent Zhuque Lab AI-Infra-Guard**
> https://github.com/Tencent/AI-Infra-Guard

- 版权：Copyright 2024-2026 Tencent Zhuque Lab
- 许可证：Apache License 2.0，全文见 `LICENSES/Apache-2.0.txt`
- 上游 NOTICE：`LICENSES/NOTICE-AI-Infra-Guard.txt`（要求保留，勿删）
- 修改内容：`build_kb.py` 将上游 YAML 规则与指纹定义**转换为 JSON 索引**（`data/fingerprints.json`、`data/vuln_index.json`），并递归展开子目录；规则正文以 YAML 原样保留在 `data/vuln/<组件>/` 下。未修改任何规则语义。
- 统计：163 条指纹、147 个组件、2581 条 CVE 规则。

引用本包或其衍生作品时，需在文档、关于页或发布说明中保留上述署名句与仓库链接（Apache-2.0 §4(d) 及上游 NOTICE 的强制要求）。

---

## 3. 本项目原创部分

`verrule.py`、`aig_tool.py`、`strix_tools.py`、`build_kb.py`、`build_skill_pack.py`、`verify_skill_pack.py`、`selftest.sh`、`tests/`、`ctf-triage`、`ctf-ai-infra` 为本项目原创。使用范围由项目方另行确定。

---

## 4. 依赖

运行期仅需 Python 3.9+ 标准库（`json`、`re`、`urllib`、`http.server`），无第三方包依赖。交叉验证工具（`crosscheck.py`，未随包分发）额外需要 `packaging`。

---

## 3. strix 1.7.0 — Apache-2.0

- 上游：本仓库以 vendored 形式内置，路径 `vendor/src/strix/`
- 许可证：Apache-2.0，全文见 `LICENSES/Apache-2.0.txt`
- 修改情况：**未改动上游源码**。所有改造都在 `src/ctf_strix/`，通过运行时替换
  `_BASE_TOOLS`、`register_agent_tools`、`_with_bounded_result` 等扩展点注入。
