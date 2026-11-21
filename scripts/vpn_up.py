#!/usr/bin/env python3
"""按实例 profile 起/拆 WireGuard 隧道（给"解题的 Claude"用的最小入口）。

为什么需要这个脚本：``ctf_strix.vpn.VpnTunnel`` 只在 ``batch_eval`` 里被调用，
单题手打时没有 CLI 入口。这里把 profile 文件直接变成一条隧道，不依赖 token、
不碰 ``/etc/resolv.conf``，也不改宿主全局 DNS。

用法::

    # 起（profile 来自 /instances/{id}/vpn-config 或平台页面下载的 .conf）
    python3 scripts/vpn_up.py up /root/vpn/<iid>.conf

    # 看
    python3 scripts/vpn_up.py show

    # 拆（幂等；换题/收工必做）
    python3 scripts/vpn_up.py down

退出码：0 = 隧道已建好且握手成功；1 = 任何一步失败（原因打印到 stderr）。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

#: 默认接口名。一个进程/一个时刻只该有一条隧道；和 batch_eval 的 wg<pid> 不冲突。
DEFAULT_IFACE = "wgctf"


def _repo_src() -> Path:
    """找到 ``ctf_strix`` 包所在的 ``src/``。

    脚本可能被单独拷到别的机器上用（例如 VPS 上的 ``/root/tools/``），
    所以按这个顺序找：

    1. 环境变量 ``CTF_STRIX_SRC``；
    2. 仓库内：``<root>/scripts/vpn_up.py`` → ``<root>/src``；
    3. 部署树默认位置 ``/root/deploy/strix-ctf-agent/src``。
    """
    env = os.environ.get("CTF_STRIX_SRC", "").strip()
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent.parent / "src"
    if (here / "ctf_strix" / "vpn.py").is_file():
        return here
    return Path("/root/deploy/strix-ctf-agent/src")


def _run(argv: list[str], timeout: float = 30.0) -> subprocess.CompletedProcess:
    """执行命令；非 root 时前置 ``sudo -n``（依赖 /etc/sudoers.d/ctfvpn 白名单）。"""
    if os.geteuid() != 0:
        argv = ["sudo", "-n", *argv]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def cmd_up(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(_repo_src()))
    from ctf_strix.vpn import VpnTunnel  # noqa: PLC0415

    conf = Path(args.conf).expanduser()
    if not conf.is_file():
        print(f"[vpn_up] profile 不存在：{conf}", file=sys.stderr)
        return 1
    text = conf.read_text(encoding="utf-8", errors="replace")
    try:
        tunnel = VpnTunnel.from_profile(text, args.iface)
    except (ValueError, KeyError) as exc:
        print(f"[vpn_up] profile 解析失败：{exc}", file=sys.stderr)
        return 1
    if not tunnel.up():
        print(
            f"[vpn_up] 隧道没起来（接口 {args.iface}，端点 {tunnel.endpoint}）\n"
            "  排查顺序：sudo -n wg show / dmesg | grep -i apparmor / "
            "getent hosts <端点主机名>",
            file=sys.stderr,
        )
        return 1
    print(f"[vpn_up] UP  iface={tunnel.iface}  addr={tunnel.address}")
    print(f"[vpn_up]      routes={', '.join(tunnel.routes) or '-'}")
    print(f"[vpn_up]      dns={', '.join(tunnel.dns) or '-'}")
    print(f"[vpn_up]      endpoint={tunnel.endpoint}")
    if tunnel.dns:
        print(
            "[vpn_up] 内网域名请这样解析（不改 /etc/resolv.conf）：\n"
            f"    dig +short @{tunnel.dns[0]} <host>.internal"
        )
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    proc = _run(["ip", "link", "del", args.iface])
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        if "Cannot find device" in msg or "not found" in msg.lower():
            print(f"[vpn_up] 接口 {args.iface} 本来就不存在（幂等）")
            return 0
        print(f"[vpn_up] 拆除失败：{msg}", file=sys.stderr)
        return 1
    print(f"[vpn_up] DOWN  iface={args.iface}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    proc = _run(["wg", "show", args.iface])
    out = (proc.stdout or "").strip()
    if not out:
        print(f"[vpn_up] 接口 {args.iface} 没起来：{(proc.stderr or '').strip()}")
        return 1
    print(out)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iface", default=DEFAULT_IFACE, help=f"接口名（默认 {DEFAULT_IFACE}）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_up = sub.add_parser("up", help="按 profile 起隧道")
    p_up.add_argument("conf", help="wg-quick 风格 profile 路径")
    p_up.set_defaults(func=cmd_up)

    p_down = sub.add_parser("down", help="拆隧道（幂等）")
    p_down.set_defaults(func=cmd_down)

    p_show = sub.add_parser("show", help="看握手状态")
    p_show.set_defaults(func=cmd_show)

    # --iface 既可由子命令也给：统一从顶层取，子命令解析后覆盖
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())