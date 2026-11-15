#!/usr/bin/env bash
# CTFY 比赛 VPS 上的调度器启动器（docs/47 §1.5 的部署契约）。
#
# 它只做三件事：把环境读对、把 compete.py 拉起来、死了就重启。
# 所有业务判断都在 compete.py 里 —— 这里不要长出第二套逻辑。
#
# 用法：
#   agent_run.sh --check     只做预检，打印清单，失败返回 1（开赛前跑这个）
#   agent_run.sh             常驻：起 compete.py，异常退出按指数退避重启
#
# systemd 与 cron 都只是"谁来调用它"的区别，见 install.sh。
set -uo pipefail

ENVF=${CTFY_ENV:-$HOME/.ctfy/agent.env}
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

say() { printf '[agent_run] %s\n' "$*"; }
fail=0
bad() { printf '[agent_run] FAIL %s\n' "$*"; fail=$((fail + 1)); }

# --- 读环境文件 -------------------------------------------------------------
# 只用 KEY=VALUE，不 source（环境文件里没有可执行的 shell，读错了也不会执行别人
# 写的东西）。值里有空格也能读，因为只按第一个 = 切分。
if [ ! -r "$ENVF" ]; then
  say "环境文件不可读：$ENVF（先从 agent.env.example 复制一份）"
  exit 2
fi
while IFS='=' read -r key val; do
  case "$key" in ''|\#*) continue ;; esac
  # 去掉行尾注释与引号，只在这两种情况下才动值。
  val=${val%%#*}
  val=${val%\"}; val=${val#\"}
  export "$key=$val"
done < "$ENVF"

# --- 预检 -------------------------------------------------------------------
need() {
  local name=$1
  if [ -z "${!name:-}" ]; then bad "缺少 $name"; fi
}
for v in CTFY_TOKEN CTFY_COMPETITION_ID LLM_API_BASE LLM_API_KEY STRIX_LLM; do
  need "$v"
done

: "${CTFY_ROOT:=$HOME/strix-ctf-agent}"
: "${CTFY_STATE_DIR:=$HOME/ctfy-state}"
: "${CTFY_LOG_DIR:=$HOME/ctfy-logs}"

[ -f "$CTFY_ROOT/scripts/compete.py" ] || bad "找不到 $CTFY_ROOT/scripts/compete.py"
[ -d "$CTFY_ROOT/src" ] || bad "找不到 $CTFY_ROOT/src"

PY=${CTFY_PYTHON:-python3}
if ! command -v "$PY" >/dev/null 2>&1; then
  bad "没有 $PY"
else
  pyver=$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)
  case "$pyver" in
    3.1[0-9]|3.[2-9][0-9]) say "python $pyver ok" ;;
    *) bad "python 版本 $pyver 太旧（要 3.10+）" ;;
  esac
  "$PY" -c 'import requests' >/dev/null 2>&1 || bad "python 缺 requests"
fi

# 状态目录必须在重启后还在：平台只保证工作目录保留（F9）。
mkdir -p "$CTFY_STATE_DIR" "$CTFY_LOG_DIR" 2>/dev/null || bad "建不了状态/日志目录"
[ -w "$CTFY_STATE_DIR" ] || bad "状态目录不可写：$CTFY_STATE_DIR"

# 磁盘：一次 10 小时的跑批会留下 agents.db 与 run 归档，少于 2G 会中途写满。
avail=$(df -Pk "$CTFY_STATE_DIR" 2>/dev/null | awk 'NR==2{print int($4/1024)}')
if [ -n "${avail:-}" ] && [ "$avail" -lt 2048 ]; then
  bad "磁盘只剩 ${avail}MB（<2G）"
fi

# WireGuard：交互式题的唯一接入方式（F12）。没有 wg 就是打不到靶机。
if ! command -v wg >/dev/null 2>&1; then
  bad "没有 wg 命令（交互式题必须走 WireGuard）"
fi
if ! command -v ip >/dev/null 2>&1; then
  say "WARN 没有 ip 命令，多主机隧道网段可能配不上"
fi

# 网关：不许填第三方中转站（F11/#79）。
case "${LLM_API_BASE:-}" in
  *paratera*|*siliconflow*|*openrouter*) bad "LLM_API_BASE 指向第三方中转站，比赛不合规：$LLM_API_BASE" ;;
  https://*) say "gateway: $LLM_API_BASE" ;;
  *) bad "LLM_API_BASE 必须 https:// 开头：${LLM_API_BASE:-<empty>}" ;;
esac

# 车道数不超过配额（F2：初选赛 3）。
lanes=${CTFY_LANES:-2}
case "$lanes" in
  ''|*[!0-9]*) bad "CTFY_LANES 不是整数：$lanes" ;;
  *) [ "$lanes" -ge 1 ] && [ "$lanes" -le 3 ] || bad "CTFY_LANES=$lanes 超出 1..3" ;;
esac

if [ "$fail" -gt 0 ]; then
  say "预检未通过（$fail 项）"
  exit 1
fi
say "预检通过：root=$CTFY_ROOT state=$CTFY_STATE_DIR lanes=$lanes until=${CTFY_UNTIL:-<never>}"
[ "$CHECK_ONLY" -eq 1 ] && exit 0

# --- 常驻循环 ---------------------------------------------------------------
cd "$CTFY_ROOT" || exit 2

# 轮转：只留最近两天、最多 20 个日志。跑批日志是取证材料，但堆满磁盘会毁掉比赛。
rotate() {
  find "$CTFY_LOG_DIR" -maxdepth 1 -name 'compete-*.log' -mtime +2 -delete 2>/dev/null
  ls -1t "$CTFY_LOG_DIR"/compete-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
}

backoff=10
while :; do
  rotate
  log="$CTFY_LOG_DIR/compete-$(date +%Y%m%d-%H%M%S).log"
  args=(
    --token "$CTFY_TOKEN"
    --competition "$CTFY_COMPETITION_ID"
    --state-dir "$CTFY_STATE_DIR"
    --lanes "$lanes"
    --wallclock "${CTFY_WALLCLOCK:-300}"
    --turns "${CTFY_TURNS:-25}"
  )
  [ -n "${CTFY_UNTIL:-}" ] && args+=(--until "$CTFY_UNTIL")
  say "启动：${args[*]//$CTFY_TOKEN/<token>} -> $log"
  "$PY" scripts/compete.py "${args[@]}" >> "$log" 2>&1
  rc=$?
  say "退出 rc=$rc（$log）"
  # 0 = 到点正常收工；其它按退避重来，退避封顶 5 分钟。
  [ "$rc" -eq 0 ] && break
  sleep "$backoff"
  backoff=$(( backoff * 2 ))
  [ "$backoff" -gt 300 ] && backoff=300
done
say "收工"