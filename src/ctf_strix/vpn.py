"""每实例一条 WireGuard 隧道——`access: vpn` 的题唯一的接入方式。

## 为什么必须有这个

SAMPLE 套题里 003 / 004 / 012 的服务地址是 ``<random>.internal``，只在内网
可达。平台的 ``/instances/{id}/vpn-config`` 会返回一份**按实例生成**的
wireguard profile（含该实例专属的私钥、对端、10.x 网段和内部 DNS）。

不接这条隧道，TCP 桥能"连上"但立刻被 reset：agent 看到的是
``banner: b''`` + ``ConnectionResetError``，然后花 300-600 秒去猜是不是
TLS、是不是端口错。SAMPLE-004 两轮共烧掉 3.2M token，全部浪费在这里。

## 为什么自己解析 profile 而不调 ``wg-quick``

``wg-quick up`` 会把 ``DNS =`` 写进 ``/etc/resolv.conf``（容器里要么失败，
要么把宿主的解析器改坏）。这里只做三件事：建接口、配地址、加一条到
``AllowedIPs`` 的路由；域名解析显式走 profile 里的 DNS 服务器，
不碰全局配置。

## 生命周期

一个进程同时只持有一条隧道（平台也只有一个实例配额）。名字带 pid，
避免两次运行撞同一个接口名；``down()`` 幂等。
"""

from __future__ import annotations

import configparser
import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def _run(argv: list[str], *, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


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
            allowed=str(peer_sec.get("AllowedIPs")).split(",")[0].strip(),
            address=addr,
            dns=dns,
        )

    # ------------------------------------------------------------------ 启停
    def up(self) -> bool:
        """建接口、配地址、加路由。

        Returns:
            是否成功。失败时只记日志——题目仍可跑，只是会像以前一样连不上，
            调用方据此把"环境不可达"和"agent 没解出"分开记。
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
        fd, path = tempfile.mkstemp(suffix=".wg")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(cfg)
            os.chmod(path, 0o600)
            steps = [
                ["ip", "link", "del", self.iface],
                ["ip", "link", "add", self.iface, "type", "wireguard"],
                ["wg", "setconf", self.iface, path],
                ["ip", "-4", "addr", "add", self.address, "dev", self.iface],
                ["ip", "link", "set", "mtu", "1420", "up", "dev", self.iface],
                ["ip", "-4", "route", "add", self.allowed, "dev", self.iface],
            ]
            for i, argv in enumerate(steps):
                proc = _run(argv)
                # 第一步是幂等清理，失败无关紧要；其余失败就是真失败。
                if proc.returncode != 0 and i > 0:
                    # 同网段的路由可能被上一条隧道留着（RTNETLINK answers:
                    # File exists），那不是失败：路已经通了。
                    if "File exists" in proc.stderr:
                        continue
                    logger.warning("vpn step failed: %s: %s", argv, proc.stderr.strip())
                    return False
            self.up_ok = True
            return True
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
