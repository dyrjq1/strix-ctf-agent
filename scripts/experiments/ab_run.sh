#!/usr/bin/env bash
# S2 A/B: 20 burned CTFARENA questions, two arms, identical everything except
# CTF_STRUCT_SIG.  Control first, treatment second, strictly serial (the
# practice suite allows one instance per team).
#
# Budgets are capped identically in both arms (--max-turns 40 --max-wallclock
# 420).  The difficulty ladder would otherwise hand a hard question 60 turns /
# 2070 s, and 8 hard questions would put one arm past four hours.  The cap is a
# control, not a tuning knob: it is the same number in both arms and it is
# recorded with the result.
set -u
cd /home/rjq/work/strix-ctf-agent || exit 1
export LLM_API_KEY=$(tr -d ' \r\n' < /home/rjq/bailian_key_ws)
export LLM_API_BASE=https://dashscope.aliyuncs.com/compatible-mode/v1
export STRIX_LLM=openai/deepseek-v4.1-flash
export STRIX_RUNTIME_BACKEND=local
export LITELLM_LOCAL_MODEL_COST_MAP=True
export PYTHONIOENCODING=utf-8
export PYTHONPATH=$PWD/src:$PWD/vendor/src
export CTFY_COMPETITION_ID=4394a10aa5d24f97a1ec3301ca718a45

for arm in control shape; do
  out="/home/rjq/ab_${arm}.jsonl"
  if [ -s "$out" ]; then
    echo "== $arm already has $(wc -l < "$out") rows, not re-running"
    continue
  fi
  echo "== arm $arm starting $(date -Is)"
  if [ "$arm" = "control" ]; then
    CTF_STRUCT_SIG=0 .venv/bin/python scripts/batch_eval.py \
      --plan /home/rjq/ab_plan.json --turns 25 --wallclock 600 \
      --max-turns 40 --max-wallclock 420 \
      --out "$out" --token "$(tr -d ' \r\n' < /home/rjq/agent_token)" \
      >> /home/rjq/ab_${arm}.log 2>&1
  else
    .venv/bin/python scripts/batch_eval.py \
      --plan /home/rjq/ab_plan.json --turns 25 --wallclock 600 \
      --max-turns 40 --max-wallclock 420 \
      --out "$out" --token "$(tr -d ' \r\n' < /home/rjq/agent_token)" \
      >> /home/rjq/ab_${arm}.log 2>&1
  fi
  echo "== arm $arm done $(date -Is): $(wc -l < "$out") rows"
done
echo "== A/B complete"