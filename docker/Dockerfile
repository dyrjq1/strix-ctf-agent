# CTFY-0001 合规镜像：把 strix-ctf-agent 装进容器。
#
# 平台只认两件事：容器能起来、能按 task.json 里的地址写出 result 文件。
# 判据在 ctfy/core/harness_conformance.py，blocking 只有 did_not_start 和
# no_result_file。这里所有设计都是为了不让这两条出现。
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# 构建期换源开关。留空 = 用官方源（GitHub Actions 在境外，走官方最快）；
# 国内构建传 --build-arg APT_MIRROR=mirrors.tuna.tsinghua.edu.cn 之类。
# 这只是构建期的事，不会留进运行时的 sources.list。
ARG APT_MIRROR=""
ARG PIP_INDEX_URL=""

# agent 会在容器里开 shell 干活，工具链必须现成。
# 缺 nmap/sqlmap 这类专用工具不致命（agent 会用 python 手写），
# 缺 curl/python3/pip 则会直接把整题卡死。
RUN set -eux; \
    if [ -n "$APT_MIRROR" ]; then \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list 2>/dev/null || true; \
    fi; \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git jq \
        file xxd binutils unzip zip \
        gdb strace ltrace \
        netcat-openbsd iproute2 dnsutils \
        vim-tiny less procps \
        libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 依赖先装，源码后拷——改代码不会让依赖层失效，重建只要几秒。
COPY requirements.lock /app/requirements.lock
COPY docker/a_tier_closure.txt /app/docker/a_tier_closure.txt
COPY docker/check_toolchain.sh /app/docker/check_toolchain.sh
RUN chmod +x /app/docker/check_toolchain.sh
# --no-deps：requirements.lock 是环境快照，里面有 fastmcp/mcp 的版本死结，
# 任何解析器都会拒绝（详见交付说明 §4）。照单装才是忠实复现。
# 装完立刻自检：pip check 看元数据，check_toolchain.sh 再逐个 import 并做
# 一次真实调用。lock 少一个传递依赖时是构建失败，而不是比赛里第一次
# from Crypto / from PIL 才失败。
RUN set -eux; \
    if [ -n "$PIP_INDEX_URL" ]; then \
        pip install --no-deps -r /app/requirements.lock -i "$PIP_INDEX_URL"; \
    else \
        pip install --no-deps -r /app/requirements.lock; \
    fi; \
    bash /app/docker/check_toolchain.sh

# 源码：vendor 里是未改动的 strix 1.7.0，src 里是 ctf_strix 改造层。
COPY vendor/src /app/vendor/src
COPY src /app/src
COPY config /app/config

ENV PYTHONPATH=/app/src:/app/vendor/src \
    STRIX_RUNTIME_BACKEND=local \
    STRIX_TELEMETRY=false \
    CTF_AISEC_DATA=/app/src/ctf_strix/aisec/data \
    CTF_SKILLS_REF=/app/src/ctf_strix/skills_strix

# 入口必须绝对路径。平台把工作目录设成它下发的那个目录，相对路径会按它解析，
# 然后以 "can't open file" 起不来（corresponds to relative_entrypoint 这条 advisory）。
COPY docker/entrypoint.sh /usr/local/bin/ctfy-entrypoint
RUN chmod +x /usr/local/bin/ctfy-entrypoint

# 非 root 跑。容器里被攻破的靶机是外部输入，不给它 root 权限。
RUN useradd -m -u 1000 -s /bin/bash agent && chown -R agent:agent /app
# 工作目录平台会挂进来，预先建好并给权限，免得挂载后只读或不可写。
RUN mkdir -p /ctfy/work && chown -R agent:agent /ctfy

USER agent

ENTRYPOINT ["/usr/local/bin/ctfy-entrypoint"]
