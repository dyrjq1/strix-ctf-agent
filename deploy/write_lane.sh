#!/usr/bin/env bash
# write_lane.sh —— 往 ~/lanes.conf 追加一条车道，key 走无回显输入。
#
#   bash write_lane.sh <名字> <base_url> <模型名>
#   bash write_lane.sh --list
#   bash write_lane.sh --remove <名字>
#
# 为什么要有它：平台会话 key 只显示一次，粘贴时不该进 shell 历史、不该出现在
# argv（ps 一眼可见）、不该被打进日志。read -s 只把它留在内存里，落盘后立即
# chmod 600。文件格式与 compete.py --lane-config 逐字一致。
#
# 环境变量 LANES_CONF 可改路径，默认 $HOME/lanes.conf。
set -u

CONF="${LANES_CONF:-$HOME/lanes.conf}"
umask 077

die() { echo "write_lane: $*" >&2; exit 1; }

mask_key() {  # 只露头四位与尾四位
  local k="$1"
  if [ "${#k}" -le 12 ]; then printf '***'; else printf '%s…%s' "${k:0:4}" "${k: -4}"; fi
}

count_lanes() { grep -cEv '^[[:space:]]*($|#)' "$CONF" 2>/dev/null || echo 0; }

case "${1:-}" in
  --list)
    [ -r "$CONF" ] || die "没有 $CONF"
    awk -F'|' '/^[[:space:]]*($|#)/ {print; next}
      {k=$3; printf "%s|%s|%s…%s|%s\n", $1, $2, substr(k,1,4), substr(k, length(k)-3), $4}' "$CONF"
    printf '车道数：%s  文件：%s\n' "$(count_lanes)" "$CONF"
    exit 0 ;;
  --remove)
    [ $# -eq 2 ] || die "用法: bash write_lane.sh --remove <名字>"
    [ -r "$CONF" ] || die "没有 $CONF"
    tmp="$(mktemp "$CONF.XXXXXX")" || die "mktemp 失败"
    awk -F'|' -v n="$2" '$1 != n' "$CONF" > "$tmp" || { rm -f "$tmp"; die "过滤失败"; }
    mv -f "$tmp" "$CONF" && chmod 600 "$CONF" || die "替换 $CONF 失败"
    printf '已移除车道 %s，剩 %s 条\n' "$2" "$(count_lanes)"
    exit 0 ;;
esac

[ $# -eq 3 ] || die "用法: bash write_lane.sh <名字> <base_url> <模型名>（--list / --remove <名字>）"
name="$1"; base="$2"; model="$3"

case "$name" in
  ''|*[!A-Za-z0-9_-]*) die "名字只能用字母数字与 _ -：$name" ;;
esac
case "$base" in
  http://*|https://*) ;;
  *) die "base 必须以 http(s):// 开头：$base" ;;
esac
[ -n "$model" ] || die "模型名不能为空"
case "$model" in *'|'*) die "模型名里不能有竖线" ;; esac

if [ -r "$CONF" ] && awk -F'|' -v n="$name" '$1==n{f=1} END{exit !f}' "$CONF"; then
  die "车道 $name 已存在；先 --remove $name 再写，或换个名字"
fi

printf '车道 %s\n  模型 %s\n  base %s\n' "$name" "$model" "$base"
printf '粘贴 %s 的会话 key（不回显、不进 shell 历史）: ' "$name"
if [ -t 0 ]; then
  IFS= read -r -s key; printf '\n'
else
  IFS= read -r key
fi
[ -n "$key" ] || die "key 为空，未写入"
case "$key" in
  *[[:space:]]*|*'|'*) die "key 里不能有空白或竖线，未写入" ;;
esac

printf '%s|%s|%s|%s\n' "$name" "$base" "$key" "$model" >> "$CONF" || die "写 $CONF 失败"
chmod 600 "$CONF" || die "chmod 600 $CONF 失败"

printf '已追加：%s|%s|%s|%s\n' "$name" "$base" "$(mask_key "$key")" "$model"
printf '车道数：%s  文件：%s（600）\n' "$(count_lanes)" "$CONF"
printf '下一步：bash vps_preflight.sh --deploy ~/deploy --bundle ~/vps-bundle --lanes-conf %s\n' "$CONF"