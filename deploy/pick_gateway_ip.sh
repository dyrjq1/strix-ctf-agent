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
#   deploy/pick_gateway_ip.sh                                  # 默认 deepseek 子域 + 已知 IP
#   deploy/pick_gateway_ip.sh zhipu.llm-next.ctfy.io           # 单个域名
#   deploy/pick_gateway_ip.sh a.llm-next.ctfy.io b.llm-next.ctfy.io 104.21.86.233 172.67.137.154
#   deploy/pick_gateway_ip.sh --dry-run <域名...>              # 只测不写 hosts
#
# 参数里长得像 IPv4 的当候选 IP，其余当域名；不给域名就默认 llm-next.ctfy.io，
# 不给 IP 就用上面两个已知节点。每个域名各自选、各自写一行钉（只替换该 host 的旧行）。
#
# 判据：每个 IP 打 3 次 GET /models（不消耗 token），要求 HTTP 200。
#      先比成功数，再比成功样本的总耗时。全失败则退出码 1，不动 hosts。
set -u

DRY=0
HOSTS=()
IPS=()
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    *[!0-9.]*|"") HOSTS+=("$a") ;;
    *) IPS+=("$a") ;;
  esac
done
[ ${#HOSTS[@]} -eq 0 ] && HOSTS=(llm-next.ctfy.io)
[ ${#IPS[@]} -eq 0 ] && IPS=(104.21.86.233 172.67.137.154)

KEY=${GATEWAY_KEY:-}
if [ -z "$KEY" ]; then
  for f in "${LANES_CONF:-}" /root/lanes.conf; do
    [ -n "$f" ] && [ -r "$f" ] || continue
    KEY=$(awk -F'|' 'NF>=4 && $1 !~ /^#/ {print $3; exit}' "$f")
    [ -n "$KEY" ] && break
  done
fi
[ -n "$KEY" ] || { echo "no gateway key (set GATEWAY_KEY or LANES_CONF)"; exit 2; }

TRIES=5
RC=0
for HOST in "${HOSTS[@]}"; do
  BEST_IP=""; BEST_OK=-1; BEST_TOTAL=999999
  # DNS 有时能给回 A（只是可能指向坏边缘）：顺手当候选，多一个选择
  CANDS=("${IPS[@]}")
  for a in $(getent ahostsv4 "$HOST" 2>/dev/null | awk '{print $1}' | sort -u); do
    case "$a" in *:*) continue ;; esac
    case " ${CANDS[*]} " in *" $a "*) ;; *) CANDS+=("$a") ;; esac
  done
  echo "== host=$HOST  tries=$TRIES  candidates=${CANDS[*]} =="
  for ip in "${CANDS[@]}"; do
    ok=0; total=0
    for i in $(seq 1 $TRIES); do
      r=$(curl -sS -m 20 -o /dev/null -w '%{http_code} %{time_total}' \
        --resolve "$HOST:443:$ip" -H "Authorization: Bearer $KEY" \
        "https://$HOST/v1/models" 2>/dev/null)
      code=${r%% *}; t=${r##* }
      [ "$code" = "200" ] && { ok=$((ok+1)); total=$(awk -v a="$total" -v b="$t" 'BEGIN{print a+b}'); }
      printf '  %-16s try %d  %-4s %ss\n' "$ip" "$i" "${code:-000}" "${t:-?}"
    done
    printf '  %-16s ok=%d/%d total=%ss\n' "$ip" "$ok" "$TRIES" "$total"
    if [ "$ok" -gt 0 ]; then
      if [ "$ok" -gt "$BEST_OK" ] || { [ "$ok" -eq "$BEST_OK" ] && \
           awk -v a="$total" -v b="$BEST_TOTAL" 'BEGIN{exit !(a<b)}'; }; then
        BEST_OK=$ok; BEST_TOTAL=$total; BEST_IP=$ip
      fi
    fi
  done

  if [ -z "$BEST_IP" ]; then
    echo "PICK_FAIL  $HOST: no edge IP answered"
    RC=1
    continue
  fi
  echo "PICK_OK  $HOST -> $BEST_IP  (ok=$BEST_OK/$TRIES total=${BEST_TOTAL}s)"
  # 2-3/5 这类边缘样本能用但会拖重试；提示换时间再跑一遍
  if [ "$BEST_OK" -lt 4 ]; then
    echo "  WARN marginal edge ($BEST_OK/$TRIES) —— 能用但会多花重试；有空再跑一次可能换到更好的节点"
  fi

  if [ "$DRY" -eq 1 ]; then continue; fi
  if [ "$(id -u)" != "0" ]; then echo "need root to rewrite /etc/hosts"; exit 2; fi

  cp /etc/hosts "/etc/hosts.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  # 只替换这一个 host 的钉行，别的厂商条目不动
  awk -v h="$HOST" '{ for (i = 2; i <= NF; i++) if ($i == h) next } { print }' /etc/hosts > /tmp/hosts.pick.$$
  cat /tmp/hosts.pick.$$ > /etc/hosts && rm -f /tmp/hosts.pick.$$
  line="$BEST_IP $HOST"
  if [ "$HOST" = "llm-next.ctfy.io" ]; then line="$line deepseek.llm-next.ctfy.io"; fi
  echo "# llm-gateway pin (pick_gateway_ip.sh $(date +%Y-%m-%dT%H:%M))" >> /etc/hosts
  echo "$line" >> /etc/hosts
  echo "  hosts: $line"
done

if [ "$DRY" -eq 1 ]; then echo "PICK_RESULT_DRYRUN"; exit $RC; fi
echo "== /etc/hosts (llm-next) =="
grep -n 'llm-next' /etc/hosts || true
echo "== verify via system resolver =="
for HOST in "${HOSTS[@]}"; do
  getent hosts "$HOST" || { echo "  RESOLVE_FAIL $HOST"; RC=1; }
done
[ "$RC" -eq 0 ] && echo "PICK_RESULT_OK" || echo "PICK_RESULT_FAIL"
exit $RC