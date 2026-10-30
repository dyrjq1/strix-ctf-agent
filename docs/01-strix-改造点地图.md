# strix 1.7.0 改造点地图（Web 能力优先）

> 结论先行：**strix 不用改一行代码，就能在无 Docker 的机器上跑起来**。
> 它已内置两个官方扩展点：`register_backend()`（换执行后端）和 `register_agent_tools()`（加工具）。
> 我们只需要在这两个点外面包一层，不需要 fork 或打补丁。

## 0. 事实基础

- 源码：`strix_agent-1.7.0-py3-none-manylinux_2_17_x86_64.whl`，43,943 行 Python，230 个文件
- 依赖：`openai-agents>=0.19,<0.20`（Agent SDK）、`litellm`、`caido-sdk-client`、`docker>=7.1.0`
- 许可：Apache-2.0（可商用改造）

代码量分布（改造优先级的重要依据）：

| 模块 | LOC | 说明 |
|---|---:|---|
| `interface/` | 18,203 | CLI + TUI + viewer，**与比赛无关，全部不动** |
| `tools/` | 10,764 | Agent 工具集，**主战场** |
| `report/` | 4,126 | 报告生成，比赛场景可裁剪 |
| `core/` | 3,504 | 编排核心 |
| `config/` | 2,022 | pydantic-settings 配置 |
| `llm/` | 1,963 | LiteLLM 封装 |
| `runtime/` | 1,088 | **沙箱后端，无 Docker 的关键** |
| `agents/` | 939 | Agent 工厂 + prompt |
| `skills/` | 300(py)+md | 漏洞知识库（Markdown 为主） |

## 1. 关键发现：两个官方扩展点

### 1.1 `strix/runtime/backends.py:79` — 可以换掉 Docker

```python
def register_backend(name, backend, *, supports_bind_mounts=False) -> None:
    """Intended for downstream users who ship their own runtime — register
    before any session_manager.create_or_reuse call."""
```

后端注册表目前**只有 docker 一个**（`backends.py:54-56`），但：
- `session_manager.create_or_reuse()` 在 `:286-287` 通过 `get_backend(settings.runtime.backend)` 取后端，名字来自环境变量 `STRIX_RUNTIME_BACKEND`（`config/settings.py:143`）
- `agents/factory.py:616` 的注释明确说明：在第一次 `build_strix_agent` 之前注册即可生效

**这意味着：写一个本机执行后端（local backend）并 `register_backend("local", ...)`，就能绕过 Docker。**

### 1.2 `strix/agents/factory.py:631` — 可以加工具

```python
def register_agent_tools(*tools) -> None:
    """Tools are added to both root and child agents, after the base set and
    before the lifecycle tool."""
```

root agent 和所有子 agent 都会拿到，不需要改 prompt 或编排逻辑。**我们的 CTF 工具（flag 提交、题目接口、爆破/字典、常见漏洞 payload 生成）从这里挂进去。**

## 2. 无 Docker 的 3 处真实阻塞（已定位到行号）

这是本次调研最有价值的部分：不是"理论上要改"，而是**具体哪里会崩**。

| # | 位置 | 现状 | 应对 |
|---|---|---|---|
| **B1** | `runtime/session_manager.py:343` | `await session.resolve_exposed_port(48080)` —— 假设 Caido 跑在容器内并通过端口映射暴露 | local backend 让 `resolve_exposed_port` 直接返回 `127.0.0.1:48080`，Caido 在宿主机跑 |
| **B2** | `runtime/caido_bootstrap.py:46` | `_login_as_guest()` 通过 `session.exec("curl", ...)` 在沙箱内取 guest token | local backend 的 `exec` 就是本机 `subprocess`，curl 本机有 → 天然兼容 |
| **B3** | `runtime/backends.py:58` | `_BIND_MOUNT_BACKENDS = {"docker"}` —— 非 bind-mount 后端走 manifest 上传路径（`session_manager.py:292-297`） | local backend 声明 `supports_bind_mounts=True`，直接用宿主机路径，避免一次文件打包上传 |

**B1、B2、B3 全部在 local backend 内部解决，不需要改 strix 源码。**

### 还需要提供的中间层

`runtime/backends.py` 的返回类型是 `tuple[Any, Any]`（client, session），session 需要实现 `agents.sandbox.session.BaseSandboxSession` 的方法集：`exec` / `write` / `read` / `resolve_exposed_port` / `start` / `stop` 等。`runtime/docker_client.py` 用的是 `agents.sandbox.sandboxes.docker.StrixDockerSandboxClient`，我们照抄它的接口形状做一个 `LocalSandboxClient`。

> **风险登记**：`BaseSandboxSession` 的方法集需要装完 SDK 后读源码确认，不能靠猜。
> 若方法集过重（>8 个必须实现的方法），退路是：不实现 BaseSandboxSession，而是**直接绕开 session_manager，自己注册一个"伪 session"**——因为 `session_manager` 只依赖鸭子类型（`session.exec(...)`、`session.resolve_exposed_port(...)`），没有强制 isinstance 检查。**已验证** `session_manager.py` 中无 `isinstance(session, BaseSandboxSession)` 断言。

## 3. Web 能力链路的复用/改写判断

比赛只考在线交互类（Web / Pwn / AI 安全），本阶段只保证 Web。

| 组件 | 位置 | 判断 | 理由 |
|---|---|---|---|
| **HTTP 拦截代理** | `tools/proxy/tools.py` (679行) + `caido_api.py` (767行) | **原样复用** | 6 个工具：`list_requests` / `view_request` / `repeat_request` / `list_sitemap` / `view_sitemap_entry` / `scope_rules`。重放任意报文（含改包）是 Web 解题的命脉，别重造 |
| **浏览器自动化** | `tools/agent_browser/` | **原样复用** | 委托 `agent-browser` CLI（见 README），不依赖 Docker |
| **Shell** | `tools/shell/` | **原样复用** | 后端换成 local 即可 |
| **漏洞知识库** | `skills/vulnerabilities/` | **原样复用 + 增量** | 23 类漏洞的 Markdown 技能包，`load_skill` 工具按需加载。TPCTF 的题型套路以新 skill 文件形式追加，不动原文件 |
| **Python 运行时** | 走 shell | 原样复用 | PoC 现场跑 |
| **报告/评分** | `report/` (4,126行) | **降级为旁路** | 比赛只要 flag。保留但不作为主输出 |
| **侦察** | `skills/reconnaissance/` | 复用 | — |
| **MCP** | `tools/mcp/` | 暂不动 | 可选扩展 |

**结论：Web 能力 ~90% 可以直接复用。我们真正的增量只有三块：local backend、platform 适配层、CTF 专用工具。**

## 3.5 实测结果（2026-10-27）

| 验证项 | 结果 | 证据 |
|---|---|---|
| 无 Docker 时 strix 的失败点 | `APIError: 500 ... http+docker://localhost/v1.47/images/create` | `scripts/verify_local_backend.py` 前置探针 |
| SDK 是否自带本机后端 | **有**：`agents.sandbox.sandboxes.unix_local.UnixLocalSandboxClient`（1,185 行，含 PTY） | site-packages 实测 |
| `register_backend("local")` 后能否建 session | **能**，`SandboxSession` 正常返回 | 验证脚本 [2] |
| 通过该 session 执行命令 | **真实输出** `strix-local-ok\n0` | 验证脚本 [3] |
| **Caido 能否在宿主机跑** | **不能（硬阻塞）** | 见下 |

### Caido 是真正的硬阻塞

- strix 的 Web 拦截代理由 **Caido** 提供，代理工具 6 件套（`list_requests` / `view_request` / `repeat_request` / `list_sitemap` / `view_sitemap_entry` / `scope_rules`）全部是 Caido GraphQL 的薄封装（`tools/proxy/tools.py`，依赖 `caido_sdk_client`）
- Caido 原本装在 strix 的 Docker 镜像里，由 `docker-entrypoint.sh` 拉起 `caido-cli`，监听容器内 `48080`
- **`caido` 和 `caido-cli` 在本机都不存在**；`github.com/caido/caido` 连续 8 个 release 的 assets 均为 **0 个**；npm 上无 `@caido/cli` 包

**结论：没有 Caido 二进制，`repeat_request`（改包重放）这条 Web 解题命脉就断了。**

三条出路，成本递增：

| 方案 | 做法 | 代价 |
|---|---|---|
| **A. 自建代理** | 注册一个 `ProxyBackend` 抽象，实现 `mitmproxy` 版 + `caido` 版 | 需改 strix（当前 `tools/proxy` 与 Caido 强耦合，**无抽象层**），约 400-600 行 |
| **B. 拿 docker 镜像里的二进制** | 从 strix 镜像 `docker cp` 出 `caido-cli` | 需要一次 Docker 可用（换台机器/一次性云主机即可） |
| **C. 不用代理** | 让 Agent 直接用 `curl`/`python-requests` 打目标 | 丢掉全部流量历史、sitemap、可视化重放；Web 能力大幅退化 |

## 4. 我们的增量（当前已落地 2 个文件）

```
/workspace
├── src/ctf_strix/
│   ├── local_backend.py      # ✅ 已实现：46 行，注册 local 后端
│   └── __init__.py
├── scripts/verify_local_backend.py   # ✅ 端到端验证，PASS
├── vendor/src/strix/          # strix 1.7.0 原样拷贝，不改一行
└── docs/01-strix-改造点地图.md
```

刻意不做的（准则 1 & 2：不猜、不投机）：
- 不做题目调度器 —— 平台协议未知，猜出来的接口必然返工
- 不做 flag 提交工具 —— 同上
- 不改 `skills/vulnerabilities/` —— 没有真题样本之前加 skill 是拍脑袋
- 不先做代理抽象层 —— **需要你先定 A/B/C 方案**，否则是在为错误的方向写 500 行

## 5. 待确认（阻塞进度）

- [ ] **代理方案选 A / B / C**（最大分叉点）
- [ ] `BaseSandboxSession` 方法集 —— 已通过 `unix_local` 规避，无需自实现
- [ ] LLM endpoint：比赛给什么网关、什么模型名
- [ ] 平台协议：取题接口、实例下发方式、flag 提交格式
