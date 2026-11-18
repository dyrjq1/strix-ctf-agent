#!/usr/bin/env bash
# 开赛日部署自检 —— 在 VPS 上跑一遍，逐项 PASS/FAIL，最后给汇总行。
#
# 为什么需要：2026-11-18 冷启动排练暴露两个"静默死"的坑——
#   1) bundle 里的 libsystemd 遮蔽宿主同名库，Ubuntu >= 24.04 上所有宿主
#      程序（coreutils/bash/curl/tar）直接 "LIBSYSTEMD_254 not found"，
#      agent 的 exec_command 全线是死的。已修（宿主目录优先）。
#   2) vpn.py 走 `sudo -n ip/wg/dig` + `ctfvpn-wg`，而 bootstrap.sh 不装
#      这些。VPS 上缺 wireguard-tools / dnsutils 或没跑
#      scripts/install_vpn_sudoers.sh，则所有 vpn 接入的题永远连不上，
#      症状只是"连不上、超时"，看起来像题目问题。
#
# 用法：
#   bash vps_preflight.sh                       # 用默认路径
#   bash vps_preflight.sh --deploy /home/ubuntu/deploy --bundle /home/ubuntu/vps-bundle
#   bash vps_preflight.sh --lanes-conf ~/lanes.conf   # 追加每条车道的真调用探针
#
# 退出码：0 = 全 PASS/SKIP；1 = 有 FAIL。
set -uo pipefail

DEPLOY="${HOME}/deploy"
BUNDLE="${HOME}/vps-bundle"
LANES_CONF=""

while [ $# -gt 0 ]; do
  case "$1" in
    --deploy) DEPLOY="$2"; shift 2 ;;
    --bundle) BUNDLE="$2"; shift 2 ;;
    --lanes-conf) LANES_CONF="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

PASS=0; FAIL=0; SKIP=0
pass() { echo "  PASS  $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $*"; SKIP=$((SKIP+1)); }
hdr()  { echo; echo "== $* =="; }

# ---------------------------------------------------------------- 1. 机器
hdr "machine"
. /etc/os-release 2>/dev/null || true
echo "  ${PRETTY_NAME:-unknown}  kernel $(uname -r)  $(nproc) CPU"
mem_mb=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
[ "${mem_mb:-0}" -ge 4000 ] && pass "memory ${mem_mb} MB" || fail "memory ${mem_mb} MB (< 4000)"
disk_g=$(df -BG --output=avail "$HOME" 2>/dev/null | tail -1 | tr -dc '0-9')
[ "${disk_g:-0}" -ge 8 ] && pass "free disk ${disk_g} G on \$HOME" || fail "free disk ${disk_g} G on \$HOME (< 8; a full run writes ~2 G)"

# ---------------------------------------------------------------- 2. bundle
hdr "bundle integrity ($BUNDLE)"
for f in repo.tar.gz venv.tar.gz py/python.tar.gz bootstrap.sh lane_launch.sh MANIFEST.sha256; do
  [ -e "$BUNDLE/$f" ] && pass "present: $f" || fail "missing: $f"
done
[ -d "$BUNDLE/debs" ] && pass "debs/ present ($(ls "$BUNDLE/debs" | wc -l) files)" || fail "debs/ missing"
if [ -f "$BUNDLE/MANIFEST.sha256" ]; then
  ( cd "$BUNDLE" && sha256sum -c MANIFEST.sha256 --quiet 2>/dev/null ) \
    && pass "MANIFEST.sha256 verifies" || fail "MANIFEST.sha256 mismatch (bundle corrupted or edited in place)"
fi

# ---------------------------------------------------------------- 3. 部署树
hdr "deployed tree ($DEPLOY)"
REPO="$DEPLOY/strix-ctf-agent"
[ -d "$REPO" ] && pass "repo dir" || fail "repo dir missing (run bootstrap.sh)"
if [ -x "$REPO/.venv/bin/python" ]; then
  pyv="$(PATH="/lib/x86_64-linux-gnu:/usr/bin:/bin:$DEPLOY/tools/usr/bin:$REPO/.venv/bin" \
         LD_LIBRARY_PATH="/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:$DEPLOY/tools/usr/lib/x86_64-linux-gnu:$DEPLOY/tools/lib/x86_64-linux-gnu" \
         "$REPO/.venv/bin/python" -V 2>&1)"
  case "$pyv" in Python\ 3.*) pass "bundled python: $pyv" ;; *) fail "bundled python broken: $pyv" ;; esac
  ( cd "$REPO" && PATH="$DEPLOY/tools/usr/bin:$REPO/.venv/bin:$PATH" \
      LD_LIBRARY_PATH="/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:$DEPLOY/tools/usr/lib/x86_64-linux-gnu:$DEPLOY/tools/lib/x86_64-linux-gnu" \
      PYTHONPATH="$REPO/src:$REPO/vendor/src" "$REPO/.venv/bin/python" -c \
      'import ctf_strix, ctf_strix.race_stop, ctf_strix.vpn, ctf_strix.autosubmit, ctf_strix.platform_env' 2>/dev/null ) \
    && pass "package imports" || fail "package imports (see traceback: PYTHONPATH/LD_LIBRARY_PATH)"
else
  fail "bundled venv python missing"
fi

# ---------------------------------------------------------------- 4. 宿主工具
hdr "host tools"
for c in ip wg wg-quick dig getent sudo timeout curl git tar; do
  p="$(command -v "$c" 2>/dev/null)"
  [ -n "$p" ] && pass "$c -> $p" || fail "$c MISSING (apt-get install iproute2 wireguard-tools dnsutils curl git)"
done

# ---------------------------------------------------------------- 5. 提权与隧道
hdr "wireguard + privilege"
if sudo -n true >/dev/null 2>&1; then
  echo "  note: passwordless sudo for everything is available"
fi
sudo -n ip link show lo >/dev/null 2>&1 && pass "sudo -n ip" || fail "sudo -n ip (run: sudo bash scripts/install_vpn_sudoers.sh)"
sudo -n wg show >/dev/null 2>&1 && pass "sudo -n wg" || fail "sudo -n wg  (whitelist allows /usr/bin/wg — install wireguard-tools, not just the bundled copy)"
sudo -n dig -v >/dev/null 2>&1 && pass "sudo -n dig" || fail "sudo -n dig (apt-get install dnsutils)"
if sudo -n ip link add wgpre0 type wireguard >/dev/null 2>&1; then
  pass "kernel supports wireguard interfaces"
  sudo -n ip link del wgpre0 >/dev/null 2>&1 || true
else
  fail "cannot create a wireguard interface (kernel module missing or CAP_NET_ADMIN denied; vpn-access challenges will be unreachable)"
fi
[ -x /usr/local/sbin/ctfvpn-wg ] && pass "/usr/local/sbin/ctfvpn-wg installed" \
  || fail "/usr/local/sbin/ctfvpn-wg missing (run: sudo bash $REPO/scripts/install_vpn_sudoers.sh)"
[ -f /etc/sudoers.d/ctfvpn ] && pass "/etc/sudoers.d/ctfvpn present" \
  || fail "/etc/sudoers.d/ctfvpn missing (run: sudo bash $REPO/scripts/install_vpn_sudoers.sh)"

# ---------------------------------------------------------------- 6. 平台
hdr "platform reachability"
code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' https://ctfy.tsinghua.edu.cn/ 2>/dev/null)
case "$code" in
  2*|3*|4*) pass "ctfy.tsinghua.edu.cn -> HTTP $code" ;;
  *)        fail "ctfy.tsinghua.edu.cn unreachable (curl code '${code:-none}')" ;;
esac
mcp_code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_me","arguments":{}}}' \
  https://ctfy.tsinghua.edu.cn/api/v1/mcp/ 2>/dev/null)
case "$mcp_code" in
  200) pass "MCP endpoint answers (no token sent: 200 means auth not enforced here)" ;;
  401|403) pass "MCP endpoint alive (HTTP $mcp_code as expected without a token)" ;;
  *) fail "MCP endpoint -> HTTP '${mcp_code:-none}'" ;;
esac

# ---------------------------------------------------------------- 7. 车道凭据
if [ -n "$LANES_CONF" ]; then
  hdr "lane probe ($LANES_CONF)"
  if [ ! -r "$LANES_CONF" ]; then
    fail "lane config not readable: $LANES_CONF"
  else
    perms=$(stat -c '%a' "$LANES_CONF" 2>/dev/null || echo '?')
    [ "$perms" = "600" ] && pass "lane config mode 600" || fail "lane config mode $perms (chmod 600)"
    # 优先用部署包自带的 python（宿主上不一定有 python3）
    PYPROBE="$REPO/.venv/bin/python"
    [ -x "$PYPROBE" ] || PYPROBE="$(command -v python3 || true)"
    [ -n "$PYPROBE" ] || fail "no python to run the lane probe with"
    n=0
    while IFS='|' read -r name base key model; do
      n=$((n+1))
      [ -z "${name:-}" ] && continue
      case "$name" in \#*) continue ;; esac
      probe=$(LLM_P_BASE="$base" LLM_P_KEY="$key" LLM_P_MODEL="$model" "$PYPROBE" - <<'PY' 2>&1
import json, os, time, urllib.request, urllib.error
base = os.environ["LLM_P_BASE"].rstrip("/")
key = os.environ["LLM_P_KEY"]
model = os.environ["LLM_P_MODEL"]
body = json.dumps({"model": model, "max_tokens": 16,
                   "messages": [{"role": "user", "content": "reply with the single word ok"}]}).encode()
req = urllib.request.Request(base + "/chat/completions", data=body,
                             headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
t0 = time.time()
try:
    with urllib.request.urlopen(req, timeout=45) as r:
        d = json.load(r)
    el = time.time() - t0
    print("HTTP %s  %.1fs  model=%s  %r" % (r.status, el, d.get("model"),
          (d.get("choices", [{}])[0].get("message", {}) or {}).get("content", "")[:40]))
except urllib.error.HTTPError as e:
    print("HTTP %s  %s" % (e.code, e.read()[:160].decode("utf-8", "replace")))
except Exception as e:
    print("ERROR %s: %s" % (type(e).__name__, e))
PY
)
      case "$probe" in
        HTTP\ 2*) pass "lane $n '$name' -> $probe" ;;
        *)        fail "lane $n '$name' -> $probe" ;;
      esac
    done < "$LANES_CONF"
  fi
else
  hdr "lane probe"
  skip "no --lanes-conf given (pass it on competition day; it costs one tiny call per lane)"
fi

# ---------------------------------------------------------------- 汇总
echo
echo "PREFLIGHT  pass=$PASS fail=$FAIL skip=$SKIP"
[ "$FAIL" -eq 0 ] && echo "PREFLIGHT_RESULT_OK" || echo "PREFLIGHT_RESULT_FAIL"
[ "$FAIL" -eq 0 ]