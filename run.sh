#!/usr/bin/env bash
# 跑一题。所有参数原样透传给 run_strix_ctf.py。
#
#   ./run.sh --target http://10.0.0.5:8080 --turns 12
#   ./run.sh --target 10.0.0.5:1337 --target-kind tcp --turns 20
#   ./run.sh --files-dir ./chal --target-kind file --turns 12
#
# 环境变量（LLM_API_KEY / LLM_API_BASE / STRIX_LLM）从 .env 读，已经 export 的优先。
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a; . ./.env; set +a
fi

if [ -z "${LLM_API_KEY:-}" ]; then
  echo "缺 LLM_API_KEY。cp .env.example .env 然后填进去。" >&2
  exit 1
fi

export PYTHONPATH=src:vendor/src
export STRIX_RUNTIME_BACKEND=local
exec .venv/bin/python scripts/run_strix_ctf.py "$@"
