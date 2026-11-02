#!/usr/bin/env bash
# 给评测机装起 WireGuard 隧道所需的**最小**权限。
#
# 为什么需要：`ip link add ... type wireguard` 与 `ip route add` 要 root，
# 而批测是无人值守的 SSH/cron 会话。用 `sudo -S` 读密码意味着密码要落到
# 进程环境或磁盘上；装全局 NOPASSWD 又等于把整台机器交出去。这里只放行
# 四个系统二进制加一个只做 setconf 的包装脚本。
#
# 另一个坑：Ubuntu 的 AppArmor profile `/etc/apparmor.d/wg` 只允许 wg 读
# `/etc/wireguard/**`，且不给 dac_override。所以 `wg setconf <if> /tmp/x`
# 在 root 下也是 `fopen: Permission denied`。`ctfvpn-wg` 把配置写进
# /etc/wireguard/ 再 setconf、随后删除，绕开这个限制而不放宽策略。
#
# 用法（需要一次交互密码）：
#     bash scripts/install_vpn_sudoers.sh
#     bash scripts/install_vpn_sudoers.sh --check     # 只校验不写
#
# 装完自检：
#     sudo -n wg show            # rc=0 表示白名单生效
#     sudo -n ip link show lo    # rc=0
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_NAME="${SUDO_USER:-${USER:-$(id -un)}}"
TARGET="/etc/sudoers.d/ctfvpn"
WRAPPER_SRC="$HERE/ctfvpn-wg"
WRAPPER_DST="/usr/local/sbin/ctfvpn-wg"
CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

RULE="${USER_NAME} ALL=(root) NOPASSWD: /usr/sbin/ip, /sbin/ip, /usr/bin/wg, /usr/bin/wg-quick, /usr/bin/dig, ${WRAPPER_DST}"

[[ -f "$WRAPPER_SRC" ]] || { echo "缺少 $WRAPPER_SRC" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$RULE" > "$tmp"
visudo -cf "$tmp" >/dev/null || { echo "sudoers 语法错误，放弃" >&2; exit 1; }
echo "规则通过 visudo 校验："
echo "  $RULE"

[[ $CHECK_ONLY -eq 1 ]] && { echo "--check：未写入任何文件"; exit 0; }

sudo install -m 0755 -o root -g root "$WRAPPER_SRC" "$WRAPPER_DST"
echo "已安装 $WRAPPER_DST"

chmod 0440 "$tmp"
chown root:root "$tmp"
sudo install -m 0440 -o root -g root "$tmp" "$TARGET"
echo "已安装 $TARGET"

echo "自检："
sudo -n wg show >/dev/null 2>&1 && echo "  sudo -n wg show        OK" || echo "  sudo -n wg show        FAILED"
sudo -n ip link show lo >/dev/null 2>&1 && echo "  sudo -n ip link        OK" || echo "  sudo -n ip link        FAILED"
echo "卸载：sudo rm -f $TARGET $WRAPPER_DST"
