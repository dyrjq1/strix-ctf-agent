"""每实例一条 WireGuard 隧道——`access: vpn` 的题唯一的接入方式。

## 为什么必须有这个

SAMPLE 套题里 003 / 004 / 012 的服务地址是 ``<random>.internal``，只在内网
可达。平台的 ``/instances/{id}/vpn-config`` 会返回一份**按实例生成**的
wireguard profile（含该实例专属的私钥、对端、10.x 网段和内部 DNS）。

不接这条隧道，TCP 桥能"连上"但立刻被 reset：agent 看到的是
``banner: b''`` + ``ConnectionResetError``，然后花 300-600 秒去猜是不是
TLS、是不是端口错。一次 run 两轮共烧掉 3.2M token，全部浪费在这里。

## 为什么自己解析 profile 而不调 ``wg-quick``

``wg-quick up`` 会把 ``DNS =`` 写进 ``/etc/resolv.conf``（容器里要么失败，
要么把宿主的解析器改坏）。这里只做三件事：建接口、配地址、加一条到
``AllowedIPs`` 的路由；域名解析显式走 profile 里的 DNS 服务器，
不碰全局配置。

## 提权

建接口/加路由要 root。这里**不读密码、不存密码**：``_run`` 在非 root 时
自动把命令前置成 ``sudo -n``，依赖管理员预先装好的 sudoers 白名单
（只放行 ``ip`` / ``wg`` / ``wg-quick`` / ``dig`` / ``ctfvpn-wg``，见
``scripts/install_vpn_sudoers.sh``）。拿不到免密就**立刻失败**并报错，
而不是挂在交互式密码提示上——批测是无人值守的，挂住等于整批卡死。

## 为什么 setconf 走 ctfvpn-wg 而不是临时文件

Ubuntu 自带的 ``/etc/apparmor.d/wg`` 只允许 ``wg`` 读
``/etc/wireguard/{,**}``，**且不给 dac_override**。于是
``wg setconf <if> /tmp/x.wg`` 即使在 root 下也是 ``fopen: Permission
denied``——``dmesg`` 里能看到 ``apparmor="DENIED" profile="wg"``。实测
踩过：隧道永远起不来，错误看起来像普通权限问题，实际是 AppArmor 的
路径白名单。

``ctfvpn-wg`` 是个二十行的 root 包装：把 stdin 写成
``/etc/wireguard/<if>.conf``（profile 明确放行），``wg setconf`` 完立刻
删除。私钥不在磁盘留存，也不必放宽 AppArmor 策略。

## 生命周期

一个进程同时只持有一条隧道（平台也只有一个实例配额）。名字带 pid，
避免两次运行撞同一个接口名；``down()`` 幂等。
"""

from __future__ import annotations

import configparser
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


#: 需要 root 才能改网络栈的子命令。只放行这四个，sudoers 白名单与之对齐。
_PRIVILEGED = {"ip", "wg", "wg-quick", "dig", "ctfvpn-wg"}


def _needs_root(argv: list[str]) -> bool:
    """这条命令是否要 root。

    Args:
        argv: 待执行的命令。

    Returns:
        True 表示非 root 时要走 ``sudo -n``。
    """
    return bool(argv) and Path(argv[0]).name in _PRIVILEGED


def _run(argv: list[str], *, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    """执行一条系统命令；非 root 时对特权命令自动加 ``sudo -n``。

    ``sudo -n`` 而非 ``sudo -S``：批测无人值守，等密码提示等于挂死。
    拿不到免密就以非零码返回，由调用方按"隧道起不来"处理。

    Args:
        argv: 命令与参数。
        timeout: 秒。

    Returns:
        ``subprocess.CompletedProcess``。
    """
    if os.geteuid() != 0 and _needs_root(argv):
        argv = ["sudo", "-n", *argv]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def allowed_ranges(raw: str | None) -> list[str]:
    """``AllowedIPs`` 的全部网段，剔除默认路由。

    多主机题（SAMPLE-023 "Split Horizon"：portal 主机 + 文件主机）要求
    agent 能访问同一场景网段里的第二台主机。旧实现只取第一条
    ``AllowedIPs``，隧道外的 .2 之外的主机全部不可达——agent 只能看到
    被桥接到 127.0.0.1 的那一台，题就变成无解的。

    默认路由（``0.0.0.0/0`` / ``::/0``）必须剔除：比赛
    ``agent_internet=deny``，全隧道等于白送外网。若 profile 只有默认
    路由，退回原值（否则隧道整条废掉）。

    Args:
        raw: profile 里 ``AllowedIPs`` 的原始字符串（逗号分隔）。

    Returns:
        要保留的网段列表，顺序与 profile 一致。
    """
    items = [x.strip() for x in str(raw or "").split(",") if x.strip()]
    kept = [x for x in items if x not in ("0.0.0.0/0", "::/0")]
    return kept or items


class VpnTunnel:
    """一份实例级 wireguard profile 的运行态。"""

    def __init__(
        self,
        *,
        iface: str,
        private_key: str,
        peer_key: str,
        endpoint: str,
        allowed: str,
        address: str,
        dns: list[str],
    ) -> None:
        self.iface = iface
        self.private_key = private_key
        self.peer_key = peer_key
        self.endpoint = endpoint
        self.allowed = allowed
        #: 要逐条加路由的网段（IPv4 过滤见 up()）。多主机题靠这里把
        #: 同一场景的第二台主机也放进隧道。
        self.routes = allowed_ranges(allowed)
        self.address = address
        self.dns = dns
        self.up_ok = False

    # ------------------------------------------------------------------ 解析
    @classmethod
    def from_profile(cls, text: str, iface: str) -> VpnTunnel:
        """解析 ``wg-quick`` 风格的 profile。

        Args:
            text: ``/instances/{id}/vpn-config`` 返回的原文。
            iface: 要创建的接口名（<=15 字符）。

        Returns:
            尚未 up 的隧道对象。

        Raises:
            ValueError: profile 缺少 wireguard 必需字段。
        """
        cp = configparser.ConfigParser()
        cp.read_string(text)
        iface_sec = cp["Interface"]
        peer_sec = cp["Peer"]
        addr = (iface_sec.get("Address") or "").split(",")[0].strip()
        dns = [x.strip() for x in (iface_sec.get("DNS") or "").split(",") if x.strip()]
        missing = [
            name
            for name, value in (
                ("Address", addr),
                ("PrivateKey", iface_sec.get("PrivateKey")),
                ("PublicKey", peer_sec.get("PublicKey")),
                ("Endpoint", peer_sec.get("Endpoint")),
                ("AllowedIPs", peer_sec.get("AllowedIPs")),
            )
            if not value
        ]
        if missing:
            raise ValueError(f"vpn profile missing {missing}")
        return cls(
            iface=iface,
            private_key=str(iface_sec.get("PrivateKey")).strip(),
            peer_key=str(peer_sec.get("PublicKey")).strip(),
            endpoint=str(peer_sec.get("Endpoint")).strip(),
            allowed=", ".join(allowed_ranges(peer_sec.get("AllowedIPs"))),
            address=addr,
            dns=dns,
        )

    # ------------------------------------------------------------------ 启停
    def up(self) -> bool:
        """建接口、配地址、加路由。

        Returns:
            是否成功。失败时只记日志——调用方据此把"环境不可达"和
            "agent 没解出"分开记。
        """
        cfg = (
            "[Interface]\n"
            f"PrivateKey = {self.private_key}\n\n"
            "[Peer]\n"
            f"PublicKey = {self.peer_key}\n"
            f"Endpoint = {self.endpoint}\n"
            f"AllowedIPs = {self.allowed}\n"
            "PersistentKeepalive = 25\n"
        )
        # 幂等清理：上一次崩掉留下的同名接口必须先拆，否则下面
        # ``ip link add`` 会直接 "File exists"。
        _run(["ip", "link", "del", self.iface])
        proc = _run(["ip", "link", "add", self.iface, "type", "wireguard"])
        if proc.returncode != 0:
            logger.warning("vpn add failed: %s", (proc.stderr or proc.stdout).strip())
            return False
        if not self._setconf(cfg):
            _run(["ip", "link", "del", self.iface])
            return False
        for argv in (
            ["ip", "-4", "addr", "add", self.address, "dev", self.iface],
            ["ip", "link", "set", "mtu", "1420", "up", "dev", self.iface],
        ):
            proc = _run(argv)
            if proc.returncode != 0:
                # 同网段的路由可能被上一条隧道留着（RTNETLINK answers:
                # File exists），那不是失败：路已经通了。
                if "File exists" in (proc.stderr or ""):
                    continue
                logger.warning(
                    "vpn step failed: %s: %s", argv, (proc.stderr or proc.stdout).strip()
                )
                _run(["ip", "link", "del", self.iface])
                return False
        for route in self.routes:
            if ":" in route:  # IPv6 网段不走 -4 路由（该隧道只配了 v4 地址）
                continue
            proc = _run(["ip", "-4", "route", "add", route, "dev", self.iface])
            if proc.returncode != 0 and "File exists" not in (proc.stderr or ""):
                logger.warning(
                    "vpn route failed: %s: %s", route, (proc.stderr or proc.stdout).strip()
                )
                _run(["ip", "link", "del", self.iface])
                return False
        self.up_ok = True
        return True

    def _setconf(self, cfg: str) -> bool:
        """把配置喂给 wg。

        优先走 ``ctfvpn-wg``（写 /etc/wireguard 后 setconf 再删），绕开
        AppArmor 对 ``wg`` 的路径白名单。机器上没装这个包装时退回临时
        文件——那在 AppArmor enforce 的机器上会失败，但至少错误来自真实
        调用，而不是我们凭空拒绝。

        Args:
            cfg: wg-quick 风格的 ``[Interface]/[Peer]`` 文本。

        Returns:
            是否成功。
        """
        wrapper = shutil.which("ctfvpn-wg") or "/usr/local/sbin/ctfvpn-wg"
        if Path(wrapper).exists():
            argv = [wrapper, self.iface]
            if os.geteuid() != 0:
                argv = ["sudo", "-n", *argv]
            proc = subprocess.run(
                argv, input=cfg, capture_output=True, text=True, timeout=20
            )
            if proc.returncode == 0:
                return True
            logger.warning(
                "vpn setconf failed via %s: %s",
                wrapper, (proc.stderr or proc.stdout).strip(),
            )
            return False

        fd, path = tempfile.mkstemp(suffix=".wg")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(cfg)
            os.chmod(path, 0o600)
            proc = _run(["wg", "setconf", self.iface, path])
            if proc.returncode == 0:
                return True
            logger.warning("vpn setconf failed: %s", (proc.stderr or proc.stdout).strip())
            return False
        finally:
            Path(path).unlink(missing_ok=True)

    def down(self) -> None:
        """拆掉接口。幂等。"""
        if not self.up_ok:
            return
        _run(["ip", "link", "del", self.iface])
        self.up_ok = False

    # ------------------------------------------------------------------ 解析
    def resolve(self, host: str) -> str:
        """用 profile 里的 DNS 解析 ``.internal`` 域名。

        Args:
            host: 服务地址（通常是 ``xxx.internal``）。

        Returns:
            解析到的 IPv4 地址；解析不出来原样返回 ``host``，让桥去报真实错误。
        """
        if not self.dns:
            return host
        for server in self.dns:
            proc = _run(["dig", "+short", "+time=3", "+tries=1", f"@{server}", host], timeout=10)
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line and line[0].isdigit() and "." in line:
                    return line
        logger.warning("vpn dns failed for %s via %s", host, self.dns)
        return host
