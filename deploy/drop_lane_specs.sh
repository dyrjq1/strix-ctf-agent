#!/bin/bash
# 把「名字|base|凭据[|模型]」的 spec 从 stdin 落到机器上（600），供 setup_lanes.sh 消费。
#
# 为什么要这个脚本：凭据要经过聊天窗口 → 本地 shell → ssh 三跳，
# 每一跳都可能因为引号/换行/编码把内容弄坏（PowerShell 内联 ssh 会把双引号吃掉，
# Windows 换行会带 \r）。这里统一用 base64 走 stdin，远端命令里不含引号，
# 落盘前做结构校验，失败就不落盘。
#
# 用法（远端）：
#   <本地生成 base64> | ssh root@HOST 'bash /root/drop_lane_specs.sh'
#   <本地生成 base64> | ssh root@HOST 'bash /root/drop_lane_specs.sh /root/other.txt'
#
# 安全：不打印明文凭据，只打印掩码；临时文件 600，成功后原子替换。
set -eu

OUT=${1:-/root/lane_specs.txt}
umask 077
TMP=$(mktemp /root/.spec.XXXXXX)
trap 'rm -f "$TMP"' EXIT

# 输入清洗（都是实测踩过的）：
#   - PowerShell 管道会在最前面塞 UTF-8 BOM（ef bb bf）→ base64 -d 直接报 invalid input
#   - 某些编码设置下整条流是 UTF-16LE（每个字符后带 \000）
#   - Windows 侧行尾带 \r；base64 本身不含空白，所以空白全删最省事
tr -d '\000' | sed '1s/^\xEF\xBB\xBF//' | tr -d ' \t\r\n' | base64 -d > "$TMP"

if [ ! -s "$TMP" ]; then
  echo "DROP_FAIL 空内容（base64 没解出来？）"
  exit 1
fi

# 结构校验：每行至少 3 段且第一段非空；空行/注释行跳过
bad=$(awk -F'|' 'BEGIN{b=0} /^[[:space:]]*$/ {next} /^#/ {next} {if (NF<3 || $1=="" || $2=="" || $3=="") b++} END{print b+0}' "$TMP")
lines=$(awk 'BEGIN{n=0} /^[[:space:]]*$/ {next} /^#/ {next} {n++} END{print n+0}' "$TMP")
if [ "$bad" != "0" ] || [ "$lines" = "0" ]; then
  echo "DROP_FAIL lines=$lines bad=$bad（每行必须 名字|base|凭据[|模型]）"
  exit 1
fi

mv "$TMP" "$OUT"
chmod 600 "$OUT"
trap - EXIT
echo "DROP_OK  lines=$lines  out=$OUT"
awk -F'|' '{printf "  %-10s %-46s key=%s…%s\n", $1, $2, substr($3,1,6), substr($3,length($3)-2)}' "$OUT"