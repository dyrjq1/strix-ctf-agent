#!/usr/bin/env bash
# 一次装好运行环境。幂等：重复跑只会校验，不会重装。
#
# 依赖全部钉在 requirements.lock 里（124 个包，来自打包时的 uv pip freeze 全量快照）。
# 优先用 uv（快 10 倍），没有就退回 pip，两种都能跑。
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
STAMP=.venv/.deps-ok

# 选索引：pypi.org 3 秒内不通就退回清华镜像。
#
# 这一步不是可选项。国内网络直连 pypi.org 经常挂死——实测 curl 15 秒超时，
# 而 uv 自己不会主动超时告警，表现就是「setup.sh 卡住不动、.venv 一直只有 80K」。
# 不先探一下，队友会以为是包坏了。
IDX="${PIP_INDEX_URL:-}"
if [ -z "$IDX" ]; then
  if curl -fsS --max-time 3 -o /dev/null https://pypi.org/simple/ 2>/dev/null; then
    IDX="https://pypi.org/simple"
  else
    IDX="https://pypi.tuna.tsinghua.edu.cn/simple"
    echo "==> pypi.org 不可达（3s 超时），改用清华镜像"
    echo "    想换源：PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple ./setup.sh"
  fi
fi
export UV_HTTP_TIMEOUT="${UV_HTTP_TIMEOUT:-60}"

if [ ! -x .venv/bin/python ]; then
  echo "==> 创建虚拟环境 .venv"
  if command -v uv >/dev/null 2>&1; then
    uv venv --python "${PYTHON_VERSION:-3.12}" .venv || uv venv .venv
  else
    "$PY" -m venv .venv
  fi
fi

if [ -f "$STAMP" ]; then
  echo "==> 依赖已装过（$STAMP）。想强制重装：rm $STAMP && ./setup.sh"
else
  # --no-deps 是必须的，不是偷懒。
  #
  # requirements.lock 是「当时能跑的那台机器的精确快照」，不是解析器的输出。
  # 里面有一处上游就存在的死结：fastmcp 4.1.4 声明 mcp>=2.3.0，而环境里装的是
  # mcp 1.30.0（strix 那边要的）。任何解析器看到这组约束都会直接拒绝：
  #   × No solution found when resolving dependencies
  # 但那套组合是实测能跑的（63 条回归 + 11 道平台题全过）。
  # 所以照单安装、不做解析——锁文件说什么就装什么，这才是忠实复现。
  echo "==> 安装依赖（requirements.lock，124 个包，源 $IDX）"
  if command -v uv >/dev/null 2>&1; then
    uv pip install --python .venv/bin/python --index-url "$IDX" --no-deps -r requirements.lock
  else
    .venv/bin/python -m pip install --upgrade pip -i "$IDX" >/dev/null
    .venv/bin/python -m pip install -i "$IDX" --no-deps -r requirements.lock
  fi
  touch "$STAMP"
fi

echo
echo "==> 装完了。下一步："
echo "    ./selftest.sh                 # 离线自检，不花 LLM 额度"
echo "    cp .env.example .env          # 填 LLM_API_KEY，然后"
echo "    ./run.sh --target http://... --turns 12"
