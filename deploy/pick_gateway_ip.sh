#!/bin/bash
# 选一个当前可用的平台网关边缘 IP 并写进 /etc/hosts。
#
# 背景：选手 VPS 的出网 DNS 把 *.llm-next.ctfy.io 判成 NXDOMAIN（内网解析器给了
# 权威样子的空答案），公共解析器也不稳，所以只能用 /etc/hosts 钉 IP。但 Cloudflare
# anycast 的不同边缘节点质量差别很大 —— 2026-11-18 实测同一时刻
# 104.21.86.233 是 10/10，172.67.137.154 是 2/6（其余卡 TLS 60-75s 后
# "Recv failure: Connection reset by peer"）。钉死一个就等于赌它不坏。
#
# 用法：
#   deploy/pick_gateway_ip.sh                       # 默认 host + 已知 IP 列表
#   deploy/pick_gateway_ip.sh deepseek.llm-next.ctfy.io 104.21.86.233 172.67.137.154
#   deploy/pick_gateway_ip.sh --dry-run             # 只测不写 hosts
#
# 判据：每个 IP 打 3 次 GET /models（不消耗 token），要求 HTTP 200。
#      先比成功数，再比成功样本的总耗时。全失败则退出码 1，不动 hosts。
set -u

HOST=${HOST_OVERRIDE:-llm-next.ctfy.io}
DRY=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    *) ARGS+=("$a") ;;
  esac
done
if [ ${#ARGS[@]} -gt 0 ]; then
  HOST=${ARGS[0]}
  IP_LIST=("${ARGS[@]:1}")
else
  IP_LIST=(104.21.86.233 172.67.137.154)
fi

KEY=${GATEWAY_KEY:-}
if [ -z "$KEY" ]; then
  for f in "${LANES_CONF:-}" /root/lanes.conf; do
    [ -n "$f" ] && [ -r "$f" ] || continue
    KEY=$(awk -F'|' 'NF>=4 && $1 !~ /^#/ {print $3; exit}' "$f")
    [ -n "$KEY" ] && break
  done
fi
[ -n "$KEY" ] || { echo "no gateway key (set GATEWAY_KEY or LANES_CONF)"; exit 2; }

TRIES=3
BEST_IP=""
BEST_OK=-1
BEST_TOTAL=999999
echo "host=$HOST  tries=$TRIES"
for ip in "${IP_LIST[@]}"; do
  ok=0; total=0
  for i in $(seq 1 $TRIES); do
    r=$(curl -sS -m 20 -o /dev/null -w '%{http_code} %{time_total}' \
      --resolve "$HOST:443:$ip" -H "Authorization: Bearer $KEY" \
      "https://$HOST/v1/models" 2>/dev/null)
    code=${r%% *}; t=${r##* }
    [ "$code" = "200" ] && { ok=$((ok+1)); total=$(awk -v a="$total" -v b="$t" 'BEGIN{print a+b}'); }
    printf '  %-16s try %d  %-4s %ss\n' "$ip" "$i" "${code:-000}" "${t:-?}"
  done
  printf '%-16s ok=%d/%d total=%ss\n' "$ip" "$ok" "$TRIES" "$total"
  if [ "$ok" -gt 0 ]; then
    # 成功数优先，其次成功样本的总耗时
    if [ "$ok" -gt "$BEST_OK" ] || { [ "$ok" -eq "$BEST_OK" ] && \
         awk -v a="$total" -v b="$BEST_TOTAL" 'BEGIN{exit !(a<b)}'; }; then
      BEST_OK=$ok; BEST_TOTAL=$total; BEST_IP=$ip
    fi
  fi
done

if [ -z "$BEST_IP" ]; then
  echo "PICK_FAIL  no edge IP answered"; exit 1
fi
echo "PICK_OK  ip=$BEST_IP  (ok=$BEST_OK/$TRIES total=${BEST_TOTAL}s)"

if [ "$DRY" -eq 1 ]; then
  echo "--dry-run: hosts unchanged"; exit 0
fi

[ "$(id -u)" = "0" ] || { echo "need root to rewrite /etc/hosts"; exit 2; }
cp /etc/hosts "/etc/hosts.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
# 只替换这一个 host 的钉行，别的厂商条目不动
awk -v h="$HOST" '{ for (i = 2; i <= NF; i++) if ($i == h) next } { print }' /etc/hosts > /tmp/hosts.pick.$$
cat /tmp/hosts.pick.$$ > /etc/hosts && rm -f /tmp/hosts.pick.$$
line="$BEST_IP $HOST"
if [ "$HOST" = "llm-next.ctfy.io" ]; then line="$line deepseek.llm-next.ctfy.io"; fi
echo "# llm-gateway pin (pick_gateway_ip.sh $(date +%Y-%m-%dT%H:%M))" >> /etc/hosts
echo "$line" >> /etc/hosts
echo "== /etc/hosts =="
grep -n 'llm-next' /etc/hosts
echo "== verify via system resolver =="
getent hosts "$HOST"
code=$(curl -sS -m 25 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $KEY" "https://$HOST/v1/models" 2>/dev/null)
echo "GET /v1/models -> ${code:-000}"
[ "$code" = "200" ] && echo "PICK_RESULT_OK" || { echo "PICK_RESULT_FAIL"; exit 1; }