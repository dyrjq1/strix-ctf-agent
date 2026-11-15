#!/usr/bin/env bash
# 把 agent_run.sh 挂成"开机即在"的服务（docs/47 §1.5）。
#
#   install.sh            有 systemd 就装 unit，否则退回 cron @reboot + nohup
#   install.sh --check    只报会装什么，不动系统
#   install.sh --uninstall  卸掉两种，哪个存在卸哪个
#
# 为什么不直接用 systemd：比赛 VPS 上我们不一定有 root，也未必有 systemd
# （容器里常见）。两条路都写，是因为比赛期间没有时间现场排障。
set -uo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUNNER=$HERE/agent_run.sh
ENVF=${CTFY_ENV:-$HOME/.ctfy/agent.env}
MODE=${1:-install}

say() { printf '[install] %s\n' "$*"; }

if [ ! -f "$RUNNER" ]; then
  say "找不到 $RUNNER"
  exit 2
fi
chmod +x "$RUNNER" 2>/dev/null

has_systemd=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  has_systemd=1
fi

UNIT=$HOME/.config/systemd/user/ctfy-agent.service
CRON_TAG='# ctfy-agent (managed by scripts/deploy/install.sh)'

# --- 卸载 -------------------------------------------------------------------
if [ "$MODE" = "--uninstall" ]; then
  if [ "$has_systemd" -eq 1 ] && [ -f "$UNIT" ]; then
    systemctl --user disable --now ctfy-agent.service 2>/dev/null
    rm -f "$UNIT"
    systemctl --user daemon-reload 2>/dev/null
    say "已卸 systemd user unit"
  fi
  if command -v crontab >/dev/null 2>&1; then
    if crontab -l 2>/dev/null | grep -qF "$CRON_TAG"; then
      crontab -l 2>/dev/null | grep -vF "$CRON_TAG" | crontab - 2>/dev/null
      say "已清 cron 条目"
    else
      say "没有 cron 条目"
    fi
  fi
  exit 0
fi

if [ ! -r "$ENVF" ]; then
  say "环境文件不存在：$ENVF（先 cp agent.env.example 过去并填好）"
  exit 2
fi

# 装之前必过一遍预检：装一个起不来的服务等于没装。
if ! CTFY_ENV="$ENVF" bash "$RUNNER" --check; then
  say "预检未过，不安装"
  exit 1
fi

if [ "$MODE" = "--check" ]; then
  say "会使用：$([ "$has_systemd" -eq 1 ] && echo "systemd user unit $UNIT" || echo "cron @reboot + nohup")"
  exit 0
fi

if [ "$has_systemd" -eq 1 ]; then
  mkdir -p "$(dirname "$UNIT")"
  # Restart=always + RestartSec：agent_run.sh 自己也会重启 compete.py，这里管的是
  # 启动器本身。两层都在，是因为单层在 OOM 与整机重启下都不可靠。
  cat > "$UNIT" <<EOF
[Unit]
Description=CTFY agent runner
After=network-online.target

[Service]
Type=simple
Environment=CTFY_ENV=$ENVF
ExecStart=/usr/bin/env bash $RUNNER
Restart=always
RestartSec=15
StandardOutput=append:%h/ctfy-logs/supervisor.log
StandardError=append:%h/ctfy-logs/supervisor.log

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload 2>/dev/null
  # 关掉输出会掩盖失败的细节，但这里只关心成败：起不来就换路，不在这里排障。
  if systemctl --user enable --now ctfy-agent.service 2>/dev/null; then
    # user unit 默认不随开机起（要 linger）。有权限就开，没权限就明说。
    if command -v loginctl >/dev/null 2>&1; then
      if loginctl enable-linger "$(id -un)" 2>/dev/null; then
        say "已开 linger，重启后会自己起来"
      else
        say "WARN 开不了 linger（要 sudo）：重启后需手动 systemctl --user start ctfy-agent"
      fi
    fi
    say "已装 systemd user unit：$UNIT"
    say "看日志：journalctl --user -u ctfy-agent -f"
    exit 0
  fi
  # 没有 user session / dbus 时 enable 必然失败（比赛 VPS 上很常见）。删掉写下的
  # unit，免得下次检查看见文件就以为装好了，然后掉到 cron 这条能跑的路上。
  rm -f "$UNIT"
  systemctl --user daemon-reload 2>/dev/null
  say "WARN systemd user unit 起不来（无 user session？），改用 cron @reboot"
fi

if ! command -v crontab >/dev/null 2>&1; then
  say "既没有可用的 systemd 也没有 crontab，只能手动起：bash $RUNNER"
  exit 1
fi
mkdir -p "$HOME/ctfy-logs"
line="@reboot CTFY_ENV=$ENVF nohup bash $RUNNER >> $HOME/ctfy-logs/supervisor.log 2>&1 & $CRON_TAG"
{ crontab -l 2>/dev/null | grep -vF "$CRON_TAG"; echo "$line"; } | crontab -
say "已装 cron @reboot 条目"
say "现在这次也要起来："
CTFY_ENV="$ENVF" nohup bash "$RUNNER" >> "$HOME/ctfy-logs/supervisor.log" 2>&1 &
say "pid $!；日志：tail -f $HOME/ctfy-logs/supervisor.log"