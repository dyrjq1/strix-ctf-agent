#!/usr/bin/env bash
# CTFY-0001 容器入口。
#
# 平台约定（ctfy/core/agent_brief.py）：
#   · 工作目录 /ctfy/work，路径同时经 CTFY_WORK_DIR 下发；
#   · task.json 在里面，result 文件写到 task.json 的 result.path（默认 result.json）；
#   · stdout 不被读取，只有那个文件被收集；
#   · no_result_file 是 blocking —— 没文件 = 平台记录一次失败 run，
#     而且它看起来像「模型放弃了」，不像「镜像不合规」。
#
# 所以这个脚本唯一不可妥协的承诺是：**无论如何 exit 前 result 文件必须在**。
# 缺模型凭据、依赖坏了、python 崩了，都要留下一份能读的文件说明原因——
# 一份写着「我没跑起来」的结果，比一个空目录有用得多。
set -uo pipefail

WORK="${CTFY_WORK_DIR:-/ctfy/work}"
TASK="${WORK}/task.json"

# result 路径以 task.json 为准。这里读是为了「连 python 都起不来」时也能写对地方。
RESULT=""
if [ -f "$TASK" ]; then
  RESULT=$(python3 - "$TASK" <<'PY' 2>/dev/null || true
import json, sys
try:
    t = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
print(((t.get("result") or {}).get("path")) or "result.json")
PY
)
fi
[ -z "$RESULT" ] && RESULT="result.json"
case "$RESULT" in
  /*) RESULT_ABS="$RESULT" ;;
  *)  RESULT_ABS="${WORK}/${RESULT}" ;;
esac

# 兜底写手：只在主流程没能写出文件时触发。
write_fallback() {
  local reason="$1"
  [ -f "$RESULT_ABS" ] && return 0
  mkdir -p "$(dirname "$RESULT_ABS")" 2>/dev/null || true
  REASON="$reason" OUT="$RESULT_ABS" python3 - <<'PY' 2>/dev/null || \
    printf '{"schema_version":3,"answers":{},"turns":0,"input_tokens":0,"output_tokens":0,"stop_reason":"error","writeup":"entrypoint fallback: %s"}\n' \
      "${reason//\"/}" > "$RESULT_ABS"
import json, os
json.dump({
    # 必须和 agent.py 的 BRIEF_SCHEMA_VERSION 一致。旧值 2 只在"主流程
    # 写完 result 之前就崩了"时可见，于是同一批 run 里两个版本号并存，
    # 复盘时看不出哪个是协议版本、哪个是兜底脚本的遗留。
    "schema_version": 3,
    # 规范字段是 input_tokens / output_tokens；`tokens` 是自造字段，
    # 平台不读，写进去只会让 result.json 看起来像另一个协议。
    "answers": {}, "turns": 0, "input_tokens": 0, "output_tokens": 0,
    "stop_reason": "error",
    "writeup": "entrypoint fallback: " + os.environ.get("REASON", "unknown"),
}, open(os.environ["OUT"], "w", encoding="utf-8"), ensure_ascii=False)
PY
}

if [ ! -f "$TASK" ]; then
  # 没有 task.json 说明不是被平台下发的（本地 docker run 自测）。仍然写文件，
  # 因为「容器能起、能写」正是 conformance 要测的全部内容。
  write_fallback "no task.json in ${WORK} (local run?)"
  echo "[ctfy] no task.json; wrote ${RESULT_ABS}" >&2
fi

# 模型凭据缺失是最常见的「容器正常但一题都做不了」。
# 提前说清楚，别让平台看到一份 stop_reason=completed 的空结果。
if [ -z "${LLM_API_KEY:-}" ] && [ -z "${STRIX_LLM:-}" ]; then
  echo "[ctfy] WARNING: neither LLM_API_KEY nor STRIX_LLM is set; agent cannot run" >&2
fi

cd "$WORK" 2>/dev/null || cd /
# 用模块文件路径而不是 -m：-m 要求包可导入，而 PYTHONPATH 一旦被平台覆盖
# （它会给容器注入自己的 env），-m 会在 import 阶段就崩，连"我崩了"都写不出来。
# 直接执行文件只需要文件在，那是镜像自己的保证。
# 外层保险丝：agent.py 里已有 SIGALRM 看门狗（_install_hard_deadline），但进程
# 卡在不可中断的系统调用里时信号救不了它。这里再加一层 coreutils timeout：
# agent 被杀后走到下面的兜底写手，result.json 仍然在——被外部强杀而没有
# result 文件是平台侧的 blocking 判据。CTFY_WALL_FUSE=0 可关闭。
if [ "${CTFY_WALL_FUSE:-7200}" -gt 0 ] 2>/dev/null; then
  timeout -s KILL "${CTFY_WALL_FUSE}" python3 /app/src/ctf_strix/agent.py
else
  python3 /app/src/ctf_strix/agent.py
fi
rc=$?

# 主流程承诺自己写文件，但崩溃/被 kill 时可能没兑现。这里补最后一手。
if [ ! -f "$RESULT_ABS" ]; then
  write_fallback "agent exited ${rc} without writing ${RESULT_ABS}"
  echo "[ctfy] agent exited ${rc}; fallback result written" >&2
fi

# 恒 exit 0：协议里 non-zero 只是 advisory，但它会让每次 dispatch 显示一条告警，
# 而「跑完但没解出」和「进程崩了」在平台侧本来就不是一回事——用退出码表达后者是错位的。
exit 0
