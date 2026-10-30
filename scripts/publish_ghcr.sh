#!/usr/bin/env bash
# 把本地仓库推到 GitHub，并由 Actions 构建镜像推 ghcr。
#
# 用法：
#   GH_TOKEN=ghp_xxx OWNER=yourname ./scripts/publish_ghcr.sh
#
# token 至少要 write:packages；要自动建仓库还要 repo。
# 脚本不会把 token 写进 .git/config —— 用 http.extraheader 一次性带上。
set -euo pipefail

TOKEN="${GH_TOKEN:?需要 GH_TOKEN 环境变量}"
OWNER="${OWNER:?需要 OWNER 环境变量（GitHub 用户名）}"
REPO="${REPO:-strix-ctf-agent}"
TAG="${TAG:-1.0.0}"

API="https://api.github.com"
echo "[1/4] 检查/创建仓库 $OWNER/$REPO"
code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" "$API/repos/$OWNER/$REPO")
if [ "$code" = "404" ]; then
  curl -s -X POST -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "$API/user/repos" \
    -d "{\"name\":\"$REPO\",\"private\":false,\"description\":\"CTF agent runtime\"}" \
    | grep -E '"full_name"|"html_url"' | head -2
elif [ "$code" = "200" ]; then
  echo "  已存在，复用"
else
  echo "  查询失败 HTTP $code" >&2
  exit 1
fi

echo "[2/4] 推送"
# 用 base64 的 basic auth，避免 token 落到 remote URL 里被 git 记住
AUTH=$(printf 'x-access-token:%s' "$TOKEN" | base64 | tr -d '\n')
git -c "http.extraheader=Authorization: basic $AUTH" \
    push --force-with-lease=false \
    "https://github.com/$OWNER/$REPO.git" "HEAD:refs/heads/main" 2>&1 \
  | grep -vE "^(Enumerating|Counting|Compressing|Writing)" || true

echo "[3/4] 触发构建"
sleep 3
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "$API/repos/$OWNER/$REPO/actions/workflows/build-image.yml/dispatches" \
  -d "{\"ref\":\"main\",\"inputs\":{\"tag\":\"$TAG\"}}" -o /dev/null -w "  dispatch HTTP %{http_code}\n"

echo "[4/4] 等构建（最多 25 分钟）"
for i in $(seq 1 100); do
  status=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$API/repos/$OWNER/$REPO/actions/runs?per_page=1" \
    | python3 -c "import json,sys; r=json.load(sys.stdin)['workflow_runs']; print(r[0]['status'], r[0]['conclusion'], r[0]['html_url']) if r else print('none')" 2>/dev/null)
  echo "  [$i] $status"
  case "$status" in
    completed\ success*) break ;;
    completed\ *) echo "  构建失败，看日志" >&2; exit 1 ;;
  esac
  sleep 15
done

echo
echo "镜像地址：ghcr.io/$OWNER/$REPO:$TAG"
echo "提权检查：ghcr 包默认继承仓库可见性（public 仓库 → public 包），"
echo "          若仓库是 private，去 Packages → 包设置里手动改成 public，否则平台拉不动。"
