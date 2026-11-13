"""把远端 CTF TCP 服务（TLS+SNI / 明文）桥到本地明文端口。

## 为什么要这一层

平台的 TCP 题有三种接入方式（见实例 `services[].access`）：

  · ``tls_sni``  —— 443 端口，必须做 TLS 且带正确的 SNI
  · ``public_port`` —— 独立公网端口，明文
  · ``vpn`` —— 需要 OpenVPN

让 agent 自己去处理这些，等于把**环境问题混进解题问题**。实测过：

  · 第一次连一个平台实例时，直接 `socket.create_connection` 拿到的是 TLS 握手
    失败或超时，因为 443 上是 TLS 而 agent 发的是明文；
  · 加 `--noproxy '*'`、`openssl s_client -servername` 这类绕法要花掉 3-5 个
    turn 才能试对。

这 3-5 个 turn 对"能不能解出题"毫无信息量，纯粹是环境税。所以把接入搬到
harness：agent 永远只看到一个 ``127.0.0.1:PORT`` 的**明文**服务，怎么连是
我们的事。

## 实现

纯标准库、多线程、无依赖。每个客户端连接开一对线程做双向转发。不加任何协议
理解——它是一个哑管道，所以对 HTTP、交互式 shell、二进制协议一视同仁。

## 会话粘性（重要，不是优化而是正确性）

同一个队伍 token 重新连上去时，平台可能把连接路由到**另一台后端**，而那台
后面是**另一个进程**——上一轮改过的状态全没了。手动解一道题的时候踩到过：
第一轮把 banner 改掉，第二轮 `curl /` 看到的是原始 banner，一眼像是"改失败了"。
真因是两轮连接落在了不同后端。

所以 `create_connection` 支持 ``sni_host``：远端 TCP 连到 **lb 主机**，但 TLS
的 SNI 填的是**实例自己的 hostname**。实测这样能让后续连接稳定回到同一后端。
不传 ``sni_host`` 就退回老行为（SNI 用连接目标的主机名）。

这条也解释了为什么 agent 必须**一次连接做完一件事**：桥只保证同一条连接内
状态连续，跨连接不保证。
"""

from __future__ import annotations

import socket
import ssl
import threading
from typing import Any

#: 单次转发块大小。8 KiB 足够，且不会让交互式服务有明显延迟。
_CHUNK = 8192


class UdpRelay:
    """把本地 UDP 端口中继到远端 ``(host, port)``。

    与 :class:`TcpBridge` 同接口（``start`` / ``stop`` / ``local_url``），
    harness 收尾逻辑不用分叉。

    为什么每个客户端源地址单独一条上游 socket：题目常要求"同一个源端口
    发第二条"。如果每条数据报都 ``sendto`` 远端，上游看到的源端口每次都换，
    服务端就认不出是同一个人；``connect`` 过的 UDP socket 让上游源端口固定。

    Args:
        host: 远端 host。
        port: 远端 port。
        listen_host: 本地监听地址，默认只监听回环。
        listen_port: 本地监听端口，0 表示让内核挑一个空闲端口。
    """

    def __init__(
        self,
        host: str,
        port: int,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
    ) -> None:
        self.host = host
        self.port = int(port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((listen_host, listen_port))
        self.listen_port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        #: 客户端源地址 → 已 connect 的上游 socket。
        self._peers: dict[tuple[str, int], socket.socket] = {}

    def start(self) -> "UdpRelay":
        """开始中继（后台线程）。

        Returns:
            self，便于链式调用。
        """
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        """停止中继并关闭所有 socket。可重复调用。"""
        self._stop.set()
        for peer in list(self._peers.values()):
            try:
                peer.close()
            except OSError:
                pass
        self._peers.clear()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def __enter__(self) -> "UdpRelay":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    @property
    def local_url(self) -> str:
        """给 agent 看的连接串（与 TcpBridge 同形）。"""
        return f"127.0.0.1:{self.listen_port}"

    # ---------------------------------------------------------------- 内部
    def _loop(self) -> None:
        import selectors

        sel = selectors.DefaultSelector()
        sel.register(self._sock, selectors.EVENT_READ, None)
        try:
            while not self._stop.is_set():
                for key, _ in sel.select(0.3):
                    if key.data is None:
                        try:
                            data, addr = self._sock.recvfrom(65535)
                        except OSError:
                            continue
                        peer = self._peers.get(addr)
                        if peer is None:
                            peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            peer.connect((self.host, self.port))
                            sel.register(peer, selectors.EVENT_READ, addr)
                            self._peers[addr] = peer
                        try:
                            peer.send(data)
                        except OSError:
                            # 上游 ICMP 不可达等：丢掉映射，下一条重建。
                            self._forget(sel, addr, peer)
                    else:
                        addr = key.data
                        peer = key.fileobj
                        try:
                            data = peer.recv(65535)
                        except OSError:
                            self._forget(sel, addr, peer)
                            continue
                        try:
                            self._sock.sendto(data, addr)
                        except OSError:
                            pass
        finally:
            for key in list(sel.get_map().values()):
                try:
                    sel.unregister(key.fileobj)
                except (KeyError, ValueError):
                    pass
            sel.close()

    def _forget(
        self, sel: Any, addr: tuple[str, int], peer: Any
    ) -> None:
        try:
            sel.unregister(peer)
        except (KeyError, ValueError):
            pass
        self._peers.pop(addr, None)
        try:
            peer.close()
        except OSError:
            pass


class TcpBridge:
    """把 ``listen_port`` 桥到远端 ``(host, port)``。

    Args:
        host: 远端 host。
        port: 远端 port。
        access: 平台的 ``services[].access``。``tls_sni`` 走 TLS+SNI，其余按明文。
        listen_host: 本地监听地址，默认只监听回环。
        listen_port: 本地监听端口，0 表示让内核挑一个空闲端口。
        sni_host: TLS 的 SNI 值（及证书校验目标）。默认等于 ``host``；
            需要"连 LB、SNI 填实例 hostname"时显式传入。
    """

    def __init__(
        self,
        host: str,
        port: int,
        access: str | None = None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        sni_host: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.access = access or ""
        self.use_tls = self.access == "tls_sni"
        # SNI 与连接目标是解耦的：连接打到 LB，SNI 填实例 hostname 才能稳定
        # 回到同一后端（见模块文档「会话粘性」）。
        self.sni_host = sni_host or host
        self._listen_host = listen_host
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((listen_host, listen_port))
        self._sock.listen(16)
        self.listen_port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---------------------------------------------------------------- 生命周期
    def start(self) -> "TcpBridge":
        """开始接受连接（后台线程）。

        Returns:
            self，便于链式调用。
        """
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        """停止监听并关闭所有资源。可重复调用。"""
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def __enter__(self) -> "TcpBridge":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    @property
    def local_url(self) -> str:
        """给 agent 看的连接串。"""
        return f"127.0.0.1:{self.listen_port}"

    # ---------------------------------------------------------------- 内部
    def _connect_remote(self) -> socket.socket:
        raw = socket.create_connection((self.host, self.port), timeout=15)
        if not self.use_tls:
            return raw
        ctx = ssl.create_default_context()
        # 平台证书是自签的，且我们只关心 SNI 路由，不关心身份——校验必然失败，
        # 关掉它。这不是安全妥协：目标本来就是我们被授权测试的靶机。
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=self.sni_host)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                return  # listen socket 已关闭
            try:
                remote = self._connect_remote()
            except Exception:  # noqa: BLE001 — 远端连不上就丢这一条连接
                try:
                    client.close()
                except OSError:
                    pass
                continue
            threading.Thread(
                target=self._pump, args=(client, remote), daemon=True
            ).start()

    @staticmethod
    def _pump(a: socket.socket, b: socket.socket) -> None:
        """双向转发，任一方向 EOF 就整体关闭。"""
        def one_way(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(_CHUNK)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                # 关掉对端写方向，让另一边读到 EOF 后自然收尾。
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=one_way, args=(b, a), daemon=True)
        t.start()
        one_way(a, b)
        t.join(timeout=5)
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass
