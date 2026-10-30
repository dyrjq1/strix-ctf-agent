"""多组件 mock 靶场 + 反例靶场：验证区分能力，而不只是「能测出组件」。

为什么需要这个文件
------------------
只测「三个组件都能被认出来」是没有意义的——任何一版按 2xx 判定的实现都能过。
真正会翻车的是三件事，这个文件逐一构造出来：

1. **串味**：三个服务同时在线、响应互有相似片段（都含 ``gradio_config``），
   工具能否各归各位。
2. **幽灵组件**：只有版本号、没有指纹依据的页面，能否不报出组件。
3. **SSRF**：靶机诱导 agent 去访问元数据服务时，闸门能否拦住。

早期版本在这里暴露过两个真实缺陷：
    - 无 matcher 的块被当成命中 → 一个靶机报出 11 个组件
    - Dify 版本在响应头 X-Version → 只读 body 永远取不到

用法::

    python -m ctf_strix.aisec.mock_multi 18000
    → gradio    http://127.0.0.1:18000
      dify      http://127.0.0.1:18001
      comfyui   http://127.0.0.1:18002
      decoy     http://127.0.0.1:18003   （反例：只有版本号，不该报出组件）
"""

from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final

#: 每个组件的路径 → 响应体。内容照抄各组件的真实特征串，
#: 保证测的是「规则对不对」，而不是「mock 好不好骗」。
PAGES: Final[dict[str, dict[str, str]]] = {
    "gradio": {
        # 特征串必须和上游规则**逐字一致**，包括分号。规则要求两个 body 同时命中：
        #   '<script>window.gradio_config = {'  与  'document.getElementsByTagName("gradio-app");'
        # 早期 mock 少写了一个分号，于是「真实规则 + 正确代码」也测不出来——
        # 那不是代码错，是靶场不真实。mock 的价值全在于此。
        "/": '<html><head><title>Gradio</title></head><body>'
             '<script>window.gradio_config = {"version":"4.44.1","components":[]};</script>'
             '<script>document.getElementsByTagName("gradio-app");</script></body></html>',
        "/config": '{"version":"4.44.1","mode":"blocks"}',
    },
    "dify": {
        "/": '<html><head><title>Dify</title><meta content="Dify" name="description"></head></html>',
        "/apps": '<html><head><title>Dify</title></head><body data-public-edition="true"></body></html>',
        "/health": '{"version":"0.6.9","status":"ok"}',
    },
    "comfyui": {
        "/": '<html><head><title>ComfyUI</title></head><body><script>'
             'window.__COMFYUI_FRONTEND_VERSION__ = "1.3.9"</script></body></html>',
        # ComfyUI 的版本不在首页，在 /system_stats —— 这条规则漏了就永远取不到版本
        "/system_stats": '{"system":{"os":"posix"},"devices":[],"comfyui_version":"0.3.27"}',
    },
    # 反例：页面上只有一个版本号，没有任何可判定的指纹特征。
    # 正确实现必须**报 0 个组件**；把 version 块当命中依据的实现会在这里翻车。
    "decoy": {
        "/": '<html><body><p>a boring static page</p>'
             '<script>window.__APP_VERSION__ = "9.9.9"</script></body></html>',
    },
}

#: 版本走响应头的组件。Dify 的真实版本就在 ``X-Version``，只读 body 永远取不到。
_HEADER_VERSION: Final[dict[str, str]] = {"dify": "X-Version"}


class H(BaseHTTPRequestHandler):
    """单组件 HTTP handler。子类通过 ``type_`` 指定自己是谁。"""

    type_ = "gradio"

    def log_message(self, *a: object) -> None:  # noqa: ANN002
        """静默访问日志：测试时不想被几千行噪声刷屏。"""

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler 的约定
        pages = PAGES[self.type_]
        body = pages.get(self.path)
        code = 200 if body else 404
        body = body or "404: Not Found"
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        hdr = _HEADER_VERSION.get(self.type_)
        if hdr:
            self.send_header(hdr, "0.6.9")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def handler_for(kind: str) -> type[H]:
    """动态生成 handler 子类。

    必须动态生成而不是复用类变量：早期版本三个服务共用一个类，
    后启动的把 ``type_`` 覆盖了，结果三个端口返回同一个组件的页面。

    Args:
        kind: :data:`PAGES` 的键。

    Returns:
        handler 类。
    """
    return type(f"H_{kind}", (H,), {"type_": kind})


def serve(base_port: int = 0) -> tuple[dict[str, str], list[ThreadingHTTPServer]]:
    """启动全部 mock 服务并返回 ``组件 → URL`` 映射与 server 列表（非阻塞）。

    端口用 ``0`` 让内核分配：测试并行跑或上一条用例没退干净时，
    固定端口会直接 ``Address already in use``——那是测试自身的脆弱，
    不是被测代码的问题。调用方拿到 server 列表后可逐个 ``shutdown()``。

    Args:
        base_port: 起始端口；0 表示由内核分配。

    Returns:
        ``(urls, servers)``。
    """
    urls: dict[str, str] = {}
    servers: list[ThreadingHTTPServer] = []
    port = base_port
    for kind in PAGES:
        # 指定端口被占时退化为内核分配，保证用例不会因端口失败
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", port), handler_for(kind))
        except OSError:
            srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(kind))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        port = srv.server_address[1] + 1
        urls[kind] = f"http://127.0.0.1:{srv.server_address[1]}"
    return urls, servers


if __name__ == "__main__":
    base = int(sys.argv[1]) if len(sys.argv) > 1 else 18000
    mapping, _ = serve(base)
    for k, u in mapping.items():
        print(f"{k:8} {u}", flush=True)
    threading.Event().wait()
