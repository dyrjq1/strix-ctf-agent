#!/bin/bash
# 开赛日一把装好车道：钉边缘 IP → 查模型名 → 原子写 600 的 lanes.conf。
#
# 这台机器除了「厂商会话凭据」以外全部就绪，所以当天只跑这一条命令。
#
# 输入：一个 spec 文件，一行一家，格式
#     名字|base|凭据[|模型]
#   - base 从会话页的 OPENAI_BASE_URL 原样抄（`https://<厂商>.<会话域名>/v1`，
#     没有 /v1 结尾会自动补）
#   - 凭据是网页上只显示一次的 pk_ 串
#   - 模型可省略：省略时用 GM 线路上 `GET /v1/models` 返回的清单来定
#     （先按厂商首选名匹配，只返回一个模型就直接用，否则报错让你显式给）
#
# 用法：
#   bash deploy/setup_lanes.sh /root/lane_specs.txt
#   bash deploy/setup_lanes.sh /root/lane_specs.txt --out /root/lanes.conf --verify
#
# 安全：凭据只进子进程 env 和 600 的 lanes.conf，不打印、不进 argv、不进日志。
set -u

SPEC=${1:-/root/lane_specs.txt}
shift || true
OUT=${LANES_CONF:-/root/lanes.conf}
VERIFY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT=$2; shift 2 ;;
    --verify) VERIFY=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
[ -r "$SPEC" ] || { echo "spec not readable: $SPEC" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "run as root (needs /etc/hosts + 600 conf)" >&2; exit 2; }

mask() { printf '%s…%s' "$(printf '%s' "$1" | cut -c1-6)" "$(printf '%s' "$1" | rev | cut -c1-3 | rev)"; }

TMP=$(mktemp /root/.lanes.XXXXXX)
trap 'rm -f "$TMP"' EXIT
chmod 600 "$TMP"

n=0
fail=0
while IFS='|' read -r name base key model; do
  name=$(printf '%s' "${name:-}" | tr -d ' \r'); base=$(printf '%s' "${base:-}" | tr -d ' \r')
  key=$(printf '%s' "${key:-}" | tr -d ' \r'); model=$(printf '%s' "${model:-}" | tr -d ' \r')
  [ -z "$name" ] && continue
  case "$name" in \#*) continue ;; esac
  n=$((n+1))
  echo "== lane $n: $name =="
  if [ -z "$base" ] || [ -z "$key" ]; then echo "  FAIL: base/key 缺失"; fail=$((fail+1)); continue; fi
  case "$base" in */v1) ;; */) base="${base%/}/v1" ;; *) base="$base/v1" ;; esac
  case "$key" in pk_*) ;; *) echo "  WARN: 凭据不是 pk_ 开头（仍是平台会话凭据吗？）" ;; esac
  echo "  base=$base  key=$(mask "$key")"

  host=$(printf '%s' "$base" | sed -E 's#^[a-z]+://##; s#/.*$##; s#:[0-9]+$##')
  if ! getent hosts "$host" >/dev/null 2>&1; then
    echo "  DNS 没有 $host → 钉边缘 IP"
    GATEWAY_KEY="$key" LANES_CONF="$OUT" bash "$HERE/pick_gateway_ip.sh" "$host" || {
      echo "  FAIL: 钉 IP 没选出可用节点"; fail=$((fail+1)); continue; }
  fi

  # 模型名：没给就用 /v1/models 现查
  models=$(curl -sS -m 30 -H "Authorization: Bearer $key" "$base/models" 2>/dev/null |
           tr ',' '\n' | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [ -z "$models" ]; then
    echo "  FAIL: $base/models 没返回模型清单（凭据过期？网关边缘又坏了？）"
    fail=$((fail+1)); continue
  fi
  echo "  models: $(printf '%s' "$models" | tr '\n' ' ')"
  if [ -z "$model" ]; then
    case "$name" in
      *deepseek*) pref="deepseek-flash" ;;
      *zhipu*|*glm*) pref="glm-5.3-flashx" ;;
      *bailian*|*qwen*) pref="qwen4-max" ;;
      *xiaomi*|*mimo*) pref="mimo-v2.6-pro" ;;
      *) pref="" ;;
    esac
    if [ -n "$pref" ] && printf '%s\n' "$models" | grep -qx -- "$pref"; then
      model=$pref
    else
      cnt=$(printf '%s\n' "$models" | grep -c .)
      if [ "$cnt" = "1" ]; then
        model=$(printf '%s\n' "$models" | head -1)
      else
        echo "  FAIL: 无法自动定模型名（首选 '$pref' 不在清单里，清单有 $cnt 个）"
        echo "        在 spec 第 4 段显式写上模型名后重跑"
        fail=$((fail+1)); continue
      fi
    fi
  elif ! printf '%s\n' "$models" | grep -qx -- "$model"; then
    echo "  WARN: 指定模型 '$model' 不在 /models 清单里，仍按你写的用"
  fi
  echo "  model=$model"
  printf '%s|%s|%s|%s\n' "$name" "$base" "$key" "$model" >> "$TMP"
done < "$SPEC"

lines=$(grep -c . "$TMP" 2>/dev/null || echo 0)
if [ "$fail" -gt 0 ] || [ "$lines" = "0" ]; then
  echo "SETUP_LANES_FAIL  ok=$lines fail=$fail（$OUT 未改动）"
  exit 1
fi

# 先备份旧的，再原子替换
[ -f "$OUT" ] && cp -p "$OUT" "$OUT.bak.$(date +%Y%m%d-%H%M%S)"
cat "$TMP" > "$OUT"
chmod 600 "$OUT"
echo "== $OUT (600) =="
awk -F'|' '{printf "  %s -> %s  model=%s  key=%s…%s\n", $1, $2, $4, substr($3,1,6), substr($3,length($3)-2)}' "$OUT"
echo "SETUP_LANES_OK  lanes=$lines  out=$OUT"

if [ "$VERIFY" -eq 1 ]; then
  echo "== lane probe via preflight =="
  PF="$HERE/vps_preflight.sh"
  if [ -f "$PF" ]; then
    ARGS=(--lanes-conf "$OUT")
    [ -d "$HOME/deploy/strix-ctf-agent" ] && ARGS+=(--deploy "$HOME/deploy")
    BUNDLE_DIR=${BUNDLE_DIR:-}
    if [ -z "$BUNDLE_DIR" ]; then
      for d in "$HOME"/vps-bundle "$HOME"/vps-bundle-*; do [ -d "$d" ] && { BUNDLE_DIR=$d; break; }; done
    fi
    [ -n "$BUNDLE_DIR" ] && ARGS+=(--bundle "$BUNDLE_DIR")
    bash "$PF" "${ARGS[@]}" 2>&1 | sed -n '/lane probe/,$p'
  else
    echo "  (vps_preflight.sh 不在 $HERE)"
  fi
fi