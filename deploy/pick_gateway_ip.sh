#!/bin/bash
# 选一个当前可用的平台网关边缘 IP 并写进 /etc/hosts。
#
# 背景：选手 VPS 的出网 DNS 把 *.llm-next.ctfy.io 判成 NXDOMAIN（内网解析器给了
# 权威样子的空答案），公共解析器也不稳，所以只能用 /etc/hosts 钉 IP。但 Cloudflare
# anycast 的不同边缘节点质量差别很大 —— 2026-11-18 实测同一时刻
# 104.21.86.233 是 10/10，172.67.137.154 是 2/6（其余卡 TLS 60-75s 后
# "Recv failure: Connection reset by peer"）。钉死一个就等于赌它不坏。
#
# 候选 IP 2026-11-20 换代：平台把网关从 Cloudflare anycast 挪到了自有出口——
#   10.0.26.75     平台内网网关（VPS 在 10.0.0.0/8 里，直连，实测 16ms 回 403）
#   8.140.195.9    公网出口（*.llm-next.ctfy.io 现在的公网 A 记录，同样 16ms）
#   202.112.238.87 llm-next.ctfy.io 的地址（子域不一定归它，实测 404）
#   旧的 104.21.86.233 / 172.67.137.154 对这批子域已全 525（SSL handshake failed），
#   留着只会白等 5 次超时，已从默认列表移除（仍可通过参数显式传入）。
#
# 用法：
#   deploy/pick_gateway_ip.sh                                  # 默认 deepseek 子域 + 已知 IP
#   deploy/pick_gateway_ip.sh zhipu.llm-next.ctfy.io           # 单个域名
#   deploy/pick_gateway_ip.sh a.llm-next.ctfy.io b.llm-next.ctfy.io 10.0.26.75
#   deploy/pick_gateway_ip.sh --dry-run <域名...>              # 只测不写 hosts
#
# 参数里长得像 IPv4 的当候选 IP，其余当域名；不给域名就默认 llm-next.ctfy.io。
# 每个域名各自选、各自写一行钉：只从行里摘掉这个 host，同一行上别的 host 原样保留
# （早期版本整行丢弃，会把 21 个厂商共用的一行一起删掉）。
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
[ ${#IPS[@]} -eq 0 ] && IPS=(10.0.26.75 8.140.195.9 202.112.238.87)
HOSTS_FILE=${HOSTS_FILE:-/etc/hosts}   # 可覆盖：便于拿副本验证改写逻辑

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
  # 区分三种失败：边缘不通（000/超时）、边缘通但上游 4xx/5xx、上游正常但慢。
  # 只有前一种是"换 IP 能解决"的；后一种是厂商/网关侧故障，换 IP 没用。
  FALLBACK_IP=""; FALLBACK_ANS=0; SOFT=0
  # DNS 有时能给回 A（只是可能指向坏边缘）：顺手当候选，多一个选择
  CANDS=("${IPS[@]}")
  for a in $(getent ahostsv4 "$HOST" 2>/dev/null | awk '{print $1}' | sort -u); do
    case "$a" in *:*) continue ;; esac
    case " ${CANDS[*]} " in *" $a "*) ;; *) CANDS+=("$a") ;; esac
  done
  echo "== host=$HOST  tries=$TRIES  candidates=${CANDS[*]} =="
  for ip in "${CANDS[@]}"; do
    ok=0; total=0; answered=0
    for i in $(seq 1 $TRIES); do
      r=$(curl -sS -m 20 -o /dev/null -w '%{http_code} %{time_total}' \
        --resolve "$HOST:443:$ip" -H "Authorization: Bearer $KEY" \
        "https://$HOST/v1/models" 2>/dev/null)
      code=${r%% *}; t=${r##* }
      [ "$code" = "200" ] && { ok=$((ok+1)); total=$(awk -v a="$total" -v b="$t" 'BEGIN{print a+b}'); }
      case "${code:-000}" in 000|"") ;; *) answered=$((answered+1)) ;; esac
      printf '  %-16s try %d  %-4s %ss\n' "$ip" "$i" "${code:-000}" "${t:-?}"
    done
    printf '  %-16s ok=%d/%d answered=%d/%d total=%ss\n' "$ip" "$ok" "$TRIES" "$answered" "$TRIES" "$total"
    if [ "$answered" -gt "$FALLBACK_ANS" ]; then FALLBACK_ANS=$answered; FALLBACK_IP=$ip; fi
    if [ "$ok" -gt 0 ]; then
      if [ "$ok" -gt "$BEST_OK" ] || { [ "$ok" -eq "$BEST_OK" ] && \
           awk -v a="$total" -v b="$BEST_TOTAL" 'BEGIN{exit !(a<b)}'; }; then
        BEST_OK=$ok; BEST_TOTAL=$total; BEST_IP=$ip
      fi
    fi
  done

  if [ -z "$BEST_IP" ]; then
    if [ -n "$FALLBACK_IP" ]; then
      # 边缘回了 HTTP（4xx/5xx）说明链路是通的 —— 换 IP 治不好上游。
      # 仍然钉一个，保证内网 DNS（对 *.llm-next.ctfy.io 是 NXDOMAIN）下能解析，
      # 否则后续错误会变成 "Could not resolve host"，掩盖真正的 502。
      echo "PICK_FAIL  $HOST: 边缘可达但上游不健康（最多 $FALLBACK_ANS/$TRIES 次拿到 HTTP 应答）"
      echo "           soft-pin -> $FALLBACK_IP（只为让域名可解析；这条车道仍判失败）"
      BEST_IP=$FALLBACK_IP; BEST_OK=0; BEST_TOTAL=0; SOFT=1
    else
      echo "PICK_FAIL  $HOST: no edge IP answered（边缘不通，换 IP 或换个时间再试）"
      RC=1
      continue
    fi
  fi
  if [ "$SOFT" -eq 0 ]; then
    echo "PICK_OK  $HOST -> $BEST_IP  (ok=$BEST_OK/$TRIES total=${BEST_TOTAL}s)"
    # 2-3/5 这类边缘样本能用但会拖重试；提示换时间再跑一遍
    if [ "$BEST_OK" -lt 4 ]; then
      echo "  WARN marginal edge ($BEST_OK/$TRIES) —— 能用但会多花重试；有空再跑一次可能换到更好的节点"
    fi
  fi

  [ "$SOFT" -eq 1 ] && RC=1   # soft-pin 只解决解析，不改变"这条车道不可用"的判定
                              # （放在 dry-run 之前：--dry-run 也必须报失败，否则赛前自检会被它骗过）
  if [ "$DRY" -eq 1 ]; then continue; fi
  if [ "$(id -u)" != "0" ]; then echo "need root to rewrite /etc/hosts"; exit 2; fi

  cp "$HOSTS_FILE" "$HOSTS_FILE.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  # 只把这个 host 从行里摘掉，同一行上别的厂商条目原样保留；摘空了才整行删除。
  # （旧写法命中即 `next`，会把 21 个厂商共用的一行整行丢掉。）
  awk -v h="$HOST" '
    {
      hit = 0
      for (i = 2; i <= NF; i++) if ($i == h) { hit = 1; break }
      if (!hit) { print; next }
      out = ""; kept = 0
      for (i = 1; i <= NF; i++) if ($i != h) { out = out (out == "" ? "" : " ") $i; kept++ }
      if (kept >= 2) print out
    }' "$HOSTS_FILE" > /tmp/hosts.pick.$$
  cat /tmp/hosts.pick.$$ > "$HOSTS_FILE" && rm -f /tmp/hosts.pick.$$
  line="$BEST_IP $HOST"
  if [ "$HOST" = "llm-next.ctfy.io" ]; then line="$line deepseek.llm-next.ctfy.io"; fi
  echo "# llm-gateway pin (pick_gateway_ip.sh $(date +%Y-%m-%dT%H:%M))" >> "$HOSTS_FILE"
  echo "$line" >> "$HOSTS_FILE"
  echo "  hosts: $line"
  [ "$SOFT" -eq 1 ] && RC=1   # soft-pin 只解决解析，不改变"这条车道不可用"的判定
done

if [ "$DRY" -eq 1 ]; then echo "PICK_RESULT_DRYRUN"; exit $RC; fi
echo "== $HOSTS_FILE (llm-next) =="
grep -n 'llm-next' "$HOSTS_FILE" || true
echo "== verify via system resolver =="
for HOST in "${HOSTS[@]}"; do
  getent hosts "$HOST" || { echo "  RESOLVE_FAIL $HOST"; RC=1; }
done
[ "$RC" -eq 0 ] && echo "PICK_RESULT_OK" || echo "PICK_RESULT_FAIL"
exit $RC