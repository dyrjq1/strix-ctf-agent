#!/usr/bin/env bash
# 平台批量评测（需要 root + unshare，因为要起 mount namespace 隔离 agent 的 shell）。
#
#   ./eval.sh --ids SAMPLE-001,SAMPLE-002 --out reports/r1.jsonl
#   ./eval.sh --out reports/all.jsonl                 # 全部 14 题
#
# 队伍 token 走文件，不走命令行参数：`ps` 是全机器可读的，SAMPLE-004 的 agent
# 就是从 ps 里抄走 token 去打平台 API 的。
#   echo 'eyJ...' > /root/.ctfy/token && chmod 600 /root/.ctfy/token
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a; . ./.env; set +a
fi

if [ -z "${LLM_API_KEY:-}" ]; then
  echo "缺 LLM_API_KEY。cp .env.example .env 然后填进去。" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "eval.sh 需要 root（mount namespace）。只想跑单题用 ./run.sh。" >&2
  exit 1
fi

export PYTHONPATH=src:vendor/src
export STRIX_RUNTIME_BACKEND=local
exec .venv/bin/python scripts/eval_sample.py --token-file "${CTF_TOKEN_FILE:-/root/.ctfy/token}" "$@"
