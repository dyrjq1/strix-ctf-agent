# strix-ctf-agent

在容器里跑的 CTF 解题 agent。上游是 [strix](https://github.com/usestrix/strix) 1.7.0，
`src/ctf_strix` 是针对 CTFY 平台契约（CTFY-0001）的改造层。

## 三个入口，先选对

| 你要做的事 | 用哪个 | 说明 |
|---|---|---|
| 平台提交测评 | 镜像地址，不用解压 | `registry.ctfy.io/f0aef9e3-3b15-4648-8b7c-e1e3c1a01f79/strix-ctf-agent:v1` |
| 本地跑题 / 批量评测 | 解压 + `./setup.sh` + `./selftest.sh` | 见下方「构建」的下一节 |
| 看代码 / 继续改 | 解压读 `src/ctf_strix/` | 上游 `vendor/` 一行未改 |

完整交接说明见包内 `交付说明.md`（场景划分、评测数据、已知短板、下一步）。

## 这个镜像的契约

平台只查两件事，而且都是 blocking：

| 判据 | 含义 |
|---|---|
| `did_not_start` | 容器起不来 |
| `no_result_file` | `$CTFY_WORK_DIR` 里没有可读的 result 文件 |

第二条最容易踩，因为「没文件」在平台上看起来像**模型放弃了**，不像镜像不合规。
所以 `docker/entrypoint.sh` 唯一不可妥协的承诺是：不管缺凭据、依赖坏了、python 崩了，
退出前 result 文件必须存在。

## 构建

```bash
docker build -f docker/Dockerfile -t strix-ctf-agent:1.0.0 .
```

国内构建加源参数（境外 CI 不用加，官方源更快）：

```bash
docker build -f docker/Dockerfile \
  --build-arg APT_MIRROR=mirrors.tuna.tsinghua.edu.cn \
  --build-arg PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ \
  -t strix-ctf-agent:1.0.0 .
```

三个设计点：

- **`pip install --no-deps`**：`requirements.lock` 是环境快照，里面有 `fastmcp` / `mcp`
  的版本死结，任何解析器都会拒绝（`No solution found`），但那套组合实测能跑。照单装才是忠实复现。
- **依赖层在源码层之前**：改代码不触发依赖重装，重建从几分钟降到几秒。
- **`ENTRYPOINT` 绝对路径**：平台会把工作目录设成它下发的那个，相对路径按它解析，然后起不来。

## 本地验证

```bash
# 1. 没有 task.json 也必须写文件
mkdir -p /tmp/w && rm -rf /tmp/w/*
docker run --rm -w /ctfy/work -e CTFY_WORK_DIR=/ctfy/work \
  -v /tmp/w:/ctfy/work strix-ctf-agent:1.0.0
cat /tmp/w/result.json

# 2. dry run，走完整链路但不调模型
mkdir -p /tmp/w2 && cat > /tmp/w2/task.json <<'JSON'
{"schema_version": 2, "dry_run": true, "run_mode": "instance",
 "challenge": {"name": "smoke"}, "scope": [], "result": {"path": "result.json"}}
JSON
docker run --rm -w /ctfy/work -e CTFY_WORK_DIR=/ctfy/work \
  -v /tmp/w2:/ctfy/work strix-ctf-agent:1.0.0
cat /tmp/w2/result.json
```

## 运行时环境变量

| 变量 | 作用 |
|---|---|
| `LLM_API_KEY` / `STRIX_LLM` | 模型凭据，至少给一个，否则一题都做不了 |
| `CTFY_WORK_DIR` | 平台下发的工作目录，默认 `/ctfy/work` |
| `CTF_SKILLS_REF` | 技能包挂载点 |
| `CTF_AISEC_DATA` | 规则库路径 |

## 目录

```
vendor/src/       上游 strix 1.7.0，未改动
src/ctf_strix/    改造层：jail、技能包、提交 sidecar、平台 API 适配
docker/           Dockerfile + entrypoint
.github/workflows Actions：构建 amd64 镜像、推 ghcr、跑 conformance 自检
```

## 许可

`vendor/` 下是上游 strix 的代码，遵循其原始许可（见 `LICENSES/`）。
`src/ctf_strix/` 为本次改造部分。
